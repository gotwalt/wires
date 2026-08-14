//! The per-topic message log: a redb database holding every envelope this node
//! has accepted for one topic, plus the per-publisher chain head.
//!
//! One database per topic, at `$WIRES_HOME/topics/<topic-hex>.db` (file mode
//! `0600`, directory mode `0700`). Two tables:
//!
//! - [`TOPIC_LOG`] — `sender[32] ‖ seq_be[8]` → the canonical JSON encoding of
//!   the [`TopicEnvelope`]. The big-endian sequence number is what makes a
//!   range scan over one sender's messages come out in chain order.
//! - [`TOPIC_HWM`] — `sender[32]` → `seq_be[8] ‖ hash[32]`, the [`ChainState`]
//!   of that publisher's highest contiguous message. Derivable from the log,
//!   kept separately so `chain_state` and `hwm_all` are point lookups rather
//!   than scans on every ingest and every replay request.
//!
//! # Single-process ownership
//!
//! **redb takes an exclusive file lock: exactly one process may hold a topic
//! database open.** This is not a detail of the storage engine that callers can
//! route around — it is why `wires tail` is the resident node (spec §7) and why
//! `wires publish` talks to it over the control socket instead of opening the
//! same file. It is also half of the seq-allocator argument: a single writer per
//! `(node, topic)` is what keeps sequence numbers from being handed out twice,
//! and a repeated `(key_version, seq)` slot is what the envelope's synthetic IV
//! exists to survive (spec §4.1). A second `wires tail` on the same
//! `$WIRES_HOME` and topic therefore fails to open, loudly, rather than forking
//! the log.
//!
//! # Fresh databases have no tables
//!
//! redb creates a table when a *write* transaction first opens it, so a database
//! that has only ever been read from — the ordinary state of a tail that has
//! joined but not yet ingested anything — has neither table. Every read path in
//! this module therefore funnels its `open_table` through [`missing_is_empty`],
//! which turns redb's `TableDoesNotExist` into "empty" and lets every other
//! table error through. The rule is one helper, not a `match` per method,
//! because the failure it prevents is silent: a read path that propagates
//! `TableDoesNotExist` makes a brand-new tail look broken, and one that
//! swallows *all* table errors makes a corrupt database look empty.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::Result;
use library::{ChainState, MessageHash, NodeId, Seq, TopicEnvelope, TopicId};
use redb::{Database, TableDefinition};

/// The message log: `sender[32] ‖ seq_be[8]` → canonical JSON envelope bytes.
///
/// Keys are fixed width so the `sender` prefix is unambiguous and a range scan
/// bounded by `sender ‖ 0…0` / `sender ‖ FF…FF` yields exactly that publisher's
/// chain, in sequence order.
pub const TOPIC_LOG: TableDefinition<&[u8], &[u8]> = TableDefinition::new("topic_log");

/// The per-publisher high-water mark: `sender[32]` → `seq_be[8] ‖ hash[32]`,
/// the encoded [`ChainState`] of the newest contiguous message from that sender.
pub const TOPIC_HWM: TableDefinition<&[u8], &[u8]> = TableDefinition::new("topic_hwm");

/// Bytes in a [`TOPIC_LOG`] key: a 32-byte sender id and a big-endian `u64` seq.
const LOG_KEY_LEN: usize = 40;

/// Bytes in a [`TOPIC_HWM`] value: a big-endian `u64` seq and a 32-byte hash.
const HWM_VALUE_LEN: usize = 40;

/// What an [`TopicStore::append`] did.
///
/// The distinction is load-bearing beyond bookkeeping: `wires tail` prints a
/// message only when the append reports [`Appended::Inserted`], which is what
/// makes deduplication structural across the live gossip path, replay catch-up,
/// and a restart that re-reads the backfill (spec §7).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Appended {
    /// The envelope was new; the log and the sender's high-water mark advanced.
    Inserted,
    /// The exact envelope was already stored at that `(sender, seq)`. Append is
    /// idempotent, so a re-delivered message is not an error.
    Duplicate,
}

/// The message log for one topic.
///
/// Holds the open redb database and the topic it belongs to; the topic is kept
/// so every entry point can reject an envelope addressed elsewhere rather than
/// silently filing it under the wrong log.
#[derive(Debug)]
pub struct TopicStore {
    /// The open database. Exclusive to this process (see the module docs).
    db: Database,
    /// Where `db` lives, for error messages and for unlinking in tests.
    path: PathBuf,
    /// The topic every envelope in `db` belongs to.
    topic: TopicId,
}

impl TopicStore {
    /// The database path for `topic` under the wires home `home`:
    /// `<home>/topics/<topic-hex>.db`.
    pub fn db_path(home: &Path, topic: TopicId) -> PathBuf {
        home.join("topics").join(format!("{}.db", topic.hex()))
    }

    /// Open (creating if absent) the log for `topic` under the wires home
    /// `home`, creating `<home>/topics` with mode `0700` and the database with
    /// mode `0600` — the log holds plaintext-recoverable ciphertext and the full
    /// membership of everyone who has ever published, so it is private.
    ///
    /// Fails if another process already holds the database (see the
    /// single-process note in the module docs); the error names the path and
    /// says which command is expected to own it.
    pub fn open(home: &Path, topic: TopicId) -> Result<Self> {
        todo!("open the topic db under home, 0700 dir / 0600 file")
    }

    /// Open (creating if absent) the log for `topic` at an explicit path,
    /// bypassing the home layout. The tests' entry point, and the escape hatch
    /// for an operator pointing at a log outside `$WIRES_HOME`.
    pub fn open_at(path: &Path, topic: TopicId) -> Result<Self> {
        todo!("open the topic db at path")
    }

    /// The topic this log belongs to.
    pub fn topic(&self) -> TopicId {
        self.topic
    }

    /// Where this log lives on disk.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Store `envelope`, advancing its sender's high-water mark.
    ///
    /// Both tables are written in **one** write transaction: a log entry whose
    /// high-water mark did not advance would re-offer the message forever, and a
    /// mark that advanced past a message that was not stored would make the gap
    /// invisible to replay.
    ///
    /// Idempotent: re-appending a byte-identical envelope at an occupied
    /// `(sender, seq)` is [`Appended::Duplicate`], not an error — the live and
    /// replay paths routinely deliver the same message twice. A *different*
    /// envelope at an occupied slot is a fork and is an **error**: the store
    /// refuses it and keeps what it has (fork = detect and refuse, spec §4.2).
    ///
    /// The caller is expected to have run
    /// [`verify`](library::TopicEnvelope::verify) and
    /// [`classify_link`](library::classify_link) first; this method is the
    /// commit step, not the ingest policy.
    pub fn append(&self, envelope: &TopicEnvelope) -> Result<Appended> {
        todo!("one write txn over TOPIC_LOG + TOPIC_HWM; duplicate ok, fork errors")
    }

    /// The chain state of `sender`'s newest contiguous message, or `None` if
    /// nothing from that sender has been stored.
    pub fn chain_state(&self, sender: NodeId) -> Result<Option<ChainState>> {
        todo!("point lookup in TOPIC_HWM")
    }

    /// The [`message_hash`](library::TopicEnvelope::message_hash) of the stored
    /// envelope at `(sender, seq)`, or `None` if that slot is empty.
    ///
    /// This is what the replay server checks a requester's presented high-water
    /// marks against: a hash that disagrees means the two sides have different
    /// histories, and the server answers from genesis so the requester's own
    /// classifier surfaces the fork instead of the divergence going unnoticed
    /// (spec §6).
    pub fn hash_at(&self, sender: NodeId, seq: Seq) -> Result<Option<MessageHash>> {
        todo!("look up TOPIC_LOG at (sender, seq) and hash it")
    }

    /// Up to `limit` of `sender`'s envelopes in sequence order, starting just
    /// after `after` — or from genesis when `after` is `None`.
    ///
    /// The replay server's read path. `limit` bounds one response; the requester
    /// asks again from its new high-water mark until a pass adds nothing.
    pub fn read_after(
        &self,
        sender: NodeId,
        after: Option<Seq>,
        limit: usize,
    ) -> Result<Vec<TopicEnvelope>> {
        todo!("range scan TOPIC_LOG over the sender prefix")
    }

    /// Every sender that has at least one stored message, in id order.
    pub fn senders(&self) -> Result<Vec<NodeId>> {
        todo!("scan TOPIC_HWM keys")
    }

    /// The high-water mark of every known sender — the local view of history
    /// that a [`ReplayFrame::Request`](library::ReplayFrame) carries.
    pub fn hwm_all(&self) -> Result<BTreeMap<NodeId, ChainState>> {
        todo!("scan TOPIC_HWM")
    }

    /// The newest `limit` envelopes across all senders, in display order.
    ///
    /// Ordered by `(timestamp, sender, seq)`: the timestamp is what a reader
    /// expects to see a transcript sorted by, and `(sender, seq)` breaks ties
    /// deterministically so two nodes with the same messages print the same
    /// backfill. Timestamps are sender-chosen and unverifiable (spec §4.1), so
    /// this is a display order only — never an ordering anything trusts.
    pub fn read_backfill(&self, limit: usize) -> Result<Vec<TopicEnvelope>> {
        todo!("merge the per-sender tails and take the newest `limit`")
    }
}

/// Map redb's "this table was never created" into `None`, leaving every other
/// table error alone. The single funnel every read path in this module uses; see
/// the module docs for why fresh databases need it.
fn missing_is_empty<T>(opened: std::result::Result<T, redb::TableError>) -> Result<Option<T>> {
    todo!("Ok(None) on TableError::TableDoesNotExist, Err otherwise")
}

/// Build a [`TOPIC_LOG`] key: `sender[32] ‖ seq_be[8]`.
fn log_key(sender: NodeId, seq: Seq) -> [u8; LOG_KEY_LEN] {
    todo!("concatenate the sender bytes and the big-endian seq")
}

/// Split a [`TOPIC_LOG`] key back into its sender and sequence number. An error
/// (never a panic) on anything that is not exactly [`LOG_KEY_LEN`] bytes: the
/// database file is not a trusted input.
fn parse_log_key(bytes: &[u8]) -> Result<(NodeId, Seq)> {
    todo!("split at 32, big-endian decode the tail")
}

/// Encode a [`ChainState`] as a [`TOPIC_HWM`] value: `seq_be[8] ‖ hash[32]`.
fn hwm_value(state: &ChainState) -> [u8; HWM_VALUE_LEN] {
    todo!("concatenate the big-endian seq and the hash bytes")
}

/// Decode a [`TOPIC_HWM`] value; an error (never a panic) on a short or
/// over-long record.
fn parse_hwm_value(bytes: &[u8]) -> Result<ChainState> {
    todo!("big-endian decode the seq, then the 32-byte hash")
}
