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

use anyhow::{Context, Result, bail};
use library::{ChainState, MessageHash, NodeId, Seq, TopicEnvelope, TopicId};
use redb::{Database, ReadableDatabase, ReadableTable, TableDefinition};

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
        let path = Self::db_path(home, topic);
        ensure_private_dir(home.join("topics").as_path())?;
        Self::open_at(&path, topic)
    }

    /// Open (creating if absent) the log for `topic` at an explicit path,
    /// bypassing the home layout. The tests' entry point, and the escape hatch
    /// for an operator pointing at a log outside `$WIRES_HOME`.
    pub fn open_at(path: &Path, topic: TopicId) -> Result<Self> {
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
            && !parent.exists()
        {
            ensure_private_dir(parent)?;
        }
        // Create the file ourselves, at 0600, *before* redb ever opens it:
        // `Database::create` would otherwise make it world-readable under the
        // usual umask and leave a window in which it is. An existing file is
        // left in place (redb adopts a zero-length one) and re-chmodded, so a
        // log written by an older build is tightened on the next open.
        create_private_file(path)?;
        let db = Database::create(path).with_context(|| {
            format!(
                "opening the topic log {} (redb locks it exclusively — `wires tail` \
                 owns a topic's log; `wires publish` goes through its control socket)",
                path.display()
            )
        })?;
        Ok(Self {
            db,
            path: path.to_path_buf(),
            topic,
        })
    }

    /// The topic this log belongs to.
    ///
    /// `#[cfg(test)]`: every production entry point compares against the field
    /// directly, so this is the fixtures' way of asserting a log was opened for
    /// the topic they asked for.
    #[cfg(test)]
    pub fn topic(&self) -> TopicId {
        self.topic
    }

    /// Where this log lives on disk.
    ///
    /// `#[cfg(test)]`: the field is what error messages interpolate; the
    /// accessor exists so the suite can assert the home layout and the `0600`
    /// mode of a file it did not choose the path of.
    #[cfg(test)]
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
    /// commit step, not the ingest policy. Because it is not the policy, it does
    /// not refuse a message that leaves a hole — it just declines to hide one:
    /// the mark tracks the highest *contiguous* message, so an out-of-order
    /// append stays behind the gap (where replay can still see it) and filling
    /// the gap later advances the mark over the whole healed run at once.
    pub fn append(&self, envelope: &TopicEnvelope) -> Result<Appended> {
        if envelope.topic != self.topic {
            bail!(
                "envelope is addressed to topic {} but this log holds topic {}",
                envelope.topic.hex(),
                self.topic.hex()
            );
        }
        let sender = envelope.sender;
        let seq = envelope.seq;
        let hash = envelope
            .message_hash()
            .context("hashing the envelope to append")?;
        let wire = envelope
            .to_wire()
            .context("encoding the envelope to append")?;
        let key = log_key(sender, seq);

        let txn = self
            .db
            .begin_write()
            .with_context(|| format!("beginning a write on {}", self.path.display()))?;

        // Scoped so both tables are dropped before the transaction is consumed.
        let inserted = {
            let mut log = txn.open_table(TOPIC_LOG).context("opening topic_log")?;
            let mut marks = txn.open_table(TOPIC_HWM).context("opening topic_hwm")?;

            match held_hash(&log, sender, seq)? {
                // Byte-identical content: the live and replay paths routinely
                // deliver the same message twice, so this is not an error.
                Some(held) if held == hash => false,
                Some(held) => bail!(
                    "fork at sender {} seq {}: already holding message {}, refusing to \
                     replace it with {} (forks are detected and refused, never resolved)",
                    sender.hex(),
                    seq.0,
                    held.hex(),
                    hash.hex()
                ),
                None => {
                    log.insert(key.as_slice(), wire.as_slice())
                        .context("writing topic_log")?;

                    // Walk the mark forward over whatever is now contiguous. In
                    // the ordinary in-order case that is exactly one step; the
                    // loop exists so that an out-of-order append leaves the mark
                    // *behind* the hole (keeping the gap visible to replay) and
                    // filling the hole later heals the whole run at once.
                    let mut state = read_mark(&marks, sender)?;
                    loop {
                        let next = match state {
                            None => Seq::ZERO,
                            Some(s) => match s.seq.checked_next() {
                                Some(next) => next,
                                // The publisher's log is full; there is no
                                // further slot to advance into.
                                None => break,
                            },
                        };
                        let found = if next == seq {
                            Some(hash)
                        } else {
                            held_hash(&log, sender, next)?
                        };
                        match found {
                            Some(h) => state = Some(ChainState::new(next, h)),
                            None => break,
                        }
                    }
                    if let Some(state) = state {
                        marks
                            .insert(sender.as_bytes().as_slice(), hwm_value(&state).as_slice())
                            .context("writing topic_hwm")?;
                    }
                    true
                }
            }
        };

        if inserted {
            txn.commit().context("committing the append")?;
            Ok(Appended::Inserted)
        } else {
            txn.abort().context("aborting a duplicate append")?;
            Ok(Appended::Duplicate)
        }
    }

    /// The chain state of `sender`'s newest contiguous message, or `None` if
    /// nothing from that sender has been stored.
    pub fn chain_state(&self, sender: NodeId) -> Result<Option<ChainState>> {
        let txn = self.read()?;
        let Some(marks) = missing_is_empty(txn.open_table(TOPIC_HWM))? else {
            return Ok(None);
        };
        read_mark(&marks, sender)
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
        let txn = self.read()?;
        let Some(log) = missing_is_empty(txn.open_table(TOPIC_LOG))? else {
            return Ok(None);
        };
        held_hash(&log, sender, seq)
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
        if limit == 0 {
            return Ok(Vec::new());
        }
        // `after` comes off the wire (a peer's presented high-water mark), so
        // "the slot after it" is checked: at `Seq::MAX` there is nothing after.
        let first = match after {
            None => Seq::ZERO,
            Some(seq) => match seq.checked_next() {
                Some(next) => next,
                None => return Ok(Vec::new()),
            },
        };
        let txn = self.read()?;
        let Some(log) = missing_is_empty(txn.open_table(TOPIC_LOG))? else {
            return Ok(Vec::new());
        };
        let start = log_key(sender, first);
        let end = log_key(sender, Seq::MAX);
        let mut out = Vec::new();
        for entry in log
            .range(start.as_slice()..=end.as_slice())
            .context("scanning topic_log")?
        {
            let (key, value) = entry.context("reading topic_log")?;
            let (found, seq) = parse_log_key(key.value())?;
            debug_assert_eq!(found, sender, "range scan escaped the sender prefix");
            out.push(decode_envelope(value.value(), sender, seq)?);
            if out.len() == limit {
                break;
            }
        }
        Ok(out)
    }

    /// Every sender that has at least one stored message, in id order.
    ///
    /// Read off the marks, so precisely: every sender with a chain, which is
    /// every sender with a message once ingest has done its job (a publisher
    /// whose *only* stored message is past a hole has no mark yet, and gaps are
    /// exactly what ingest refuses to create — spec §6).
    pub fn senders(&self) -> Result<Vec<NodeId>> {
        Ok(self.hwm_all()?.into_keys().collect())
    }

    /// The high-water mark of every known sender — the local view of history
    /// that a [`ReplayFrame::Request`](library::ReplayFrame) carries.
    pub fn hwm_all(&self) -> Result<BTreeMap<NodeId, ChainState>> {
        let txn = self.read()?;
        let Some(marks) = missing_is_empty(txn.open_table(TOPIC_HWM))? else {
            return Ok(BTreeMap::new());
        };
        let mut out = BTreeMap::new();
        for entry in marks.iter().context("scanning topic_hwm")? {
            let (key, value) = entry.context("reading topic_hwm")?;
            out.insert(
                parse_sender_key(key.value())?,
                parse_hwm_value(value.value())?,
            );
        }
        Ok(out)
    }

    /// The newest `limit` envelopes across all senders, in display order.
    ///
    /// Ordered by `(timestamp, sender, seq)`: the timestamp is what a reader
    /// expects to see a transcript sorted by, and `(sender, seq)` breaks ties
    /// deterministically so two nodes with the same messages print the same
    /// backfill. Timestamps are sender-chosen and unverifiable (spec §4.1), so
    /// this is a display order only — never an ordering anything trusts.
    ///
    /// Merging on a sender-chosen key means reading the whole log: there is no
    /// index that is already in timestamp order, and per-sender tails cannot be
    /// truncated before the merge without risking dropping a message that sorts
    /// into the window. This runs once, at `wires tail` startup, over a log with
    /// no retention policy yet (out of scope, restart.md) — the day it needs to
    /// be incremental is the day retention lands.
    pub fn read_backfill(&self, limit: usize) -> Result<Vec<TopicEnvelope>> {
        if limit == 0 {
            return Ok(Vec::new());
        }
        let txn = self.read()?;
        let Some(log) = missing_is_empty(txn.open_table(TOPIC_LOG))? else {
            return Ok(Vec::new());
        };
        let mut all = Vec::new();
        for entry in log.iter().context("scanning topic_log")? {
            let (key, value) = entry.context("reading topic_log")?;
            let (sender, seq) = parse_log_key(key.value())?;
            all.push(decode_envelope(value.value(), sender, seq)?);
        }
        all.sort_by_key(|env| (env.timestamp, env.sender, env.seq));
        if all.len() > limit {
            all.drain(..all.len() - limit);
        }
        Ok(all)
    }

    /// Begin a read transaction, naming the database in any failure.
    fn read(&self) -> Result<redb::ReadTransaction> {
        self.db
            .begin_read()
            .with_context(|| format!("beginning a read on {}", self.path.display()))
    }
}

/// Map redb's "this table was never created" into `None`, leaving every other
/// table error alone. The single funnel every read path in this module uses; see
/// the module docs for why fresh databases need it.
fn missing_is_empty<T>(opened: std::result::Result<T, redb::TableError>) -> Result<Option<T>> {
    match opened {
        Ok(table) => Ok(Some(table)),
        Err(redb::TableError::TableDoesNotExist(_)) => Ok(None),
        Err(e) => Err(e).context("opening a topic table"),
    }
}

/// The [`ChainState`] stored for `sender`, or `None` when that sender has no
/// mark yet. Shared by the read path and the in-transaction mark advance.
fn read_mark<T>(marks: &T, sender: NodeId) -> Result<Option<ChainState>>
where
    T: ReadableTable<&'static [u8], &'static [u8]>,
{
    let Some(value) = marks
        .get(sender.as_bytes().as_slice())
        .context("reading topic_hwm")?
    else {
        return Ok(None);
    };
    Ok(Some(parse_hwm_value(value.value())?))
}

/// The [`TopicEnvelope::message_hash`] of whatever is stored at `(sender, seq)`,
/// or `None` when the slot is empty. Shared by [`TopicStore::hash_at`] and the
/// duplicate/fork decision in [`TopicStore::append`], so the two can never
/// disagree about what "the same message" means.
fn held_hash<T>(log: &T, sender: NodeId, seq: Seq) -> Result<Option<MessageHash>>
where
    T: ReadableTable<&'static [u8], &'static [u8]>,
{
    let key = log_key(sender, seq);
    let Some(value) = log.get(key.as_slice()).context("reading topic_log")? else {
        return Ok(None);
    };
    let envelope = decode_envelope(value.value(), sender, seq)?;
    Ok(Some(envelope.message_hash().with_context(|| {
        format!("hashing the stored envelope at {}/{}", sender.hex(), seq.0)
    })?))
}

/// Parse a stored envelope, naming the slot it came from: a database that has
/// been corrupted or hand-edited is a bad input, not a panic.
fn decode_envelope(bytes: &[u8], sender: NodeId, seq: Seq) -> Result<TopicEnvelope> {
    TopicEnvelope::from_wire(bytes).with_context(|| {
        format!(
            "decoding the stored envelope at sender {} seq {}",
            sender.hex(),
            seq.0
        )
    })
}

/// Build a [`TOPIC_LOG`] key: `sender[32] ‖ seq_be[8]`.
fn log_key(sender: NodeId, seq: Seq) -> [u8; LOG_KEY_LEN] {
    let mut key = [0u8; LOG_KEY_LEN];
    key[..32].copy_from_slice(sender.as_bytes());
    key[32..].copy_from_slice(&seq.0.to_be_bytes());
    key
}

/// Split a [`TOPIC_LOG`] key back into its sender and sequence number. An error
/// (never a panic) on anything that is not exactly [`LOG_KEY_LEN`] bytes: the
/// database file is not a trusted input.
fn parse_log_key(bytes: &[u8]) -> Result<(NodeId, Seq)> {
    if bytes.len() != LOG_KEY_LEN {
        bail!(
            "malformed topic_log key: {} bytes, expected {LOG_KEY_LEN}",
            bytes.len()
        );
    }
    let (sender, seq) = bytes.split_at(32);
    Ok((
        NodeId::from_bytes(sender.try_into().expect("32-byte split")),
        Seq(u64::from_be_bytes(seq.try_into().expect("8-byte split"))),
    ))
}

/// Read a [`TOPIC_HWM`] key back as a sender id; same untrusted-input rule as
/// [`parse_log_key`].
fn parse_sender_key(bytes: &[u8]) -> Result<NodeId> {
    let bytes: [u8; 32] = bytes.try_into().map_err(|_| {
        anyhow::anyhow!(
            "malformed topic_hwm key: {} bytes, expected 32",
            bytes.len()
        )
    })?;
    Ok(NodeId::from_bytes(bytes))
}

/// Encode a [`ChainState`] as a [`TOPIC_HWM`] value: `seq_be[8] ‖ hash[32]`.
fn hwm_value(state: &ChainState) -> [u8; HWM_VALUE_LEN] {
    let mut value = [0u8; HWM_VALUE_LEN];
    value[..8].copy_from_slice(&state.seq.0.to_be_bytes());
    value[8..].copy_from_slice(state.hash.as_bytes());
    value
}

/// Decode a [`TOPIC_HWM`] value; an error (never a panic) on a short or
/// over-long record.
fn parse_hwm_value(bytes: &[u8]) -> Result<ChainState> {
    if bytes.len() != HWM_VALUE_LEN {
        bail!(
            "malformed topic_hwm value: {} bytes, expected {HWM_VALUE_LEN}",
            bytes.len()
        );
    }
    let (seq, hash) = bytes.split_at(8);
    Ok(ChainState::new(
        Seq(u64::from_be_bytes(seq.try_into().expect("8-byte split"))),
        MessageHash::from_bytes(hash.try_into().expect("32-byte split")),
    ))
}

/// Create `dir` (and its parents) with mode `0700`.
fn ensure_private_dir(dir: &Path) -> Result<()> {
    std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    set_mode(dir, 0o700);
    Ok(())
}

/// Create `path` at mode `0600` if it does not exist, and tighten it if it
/// does. `create_new` so the create and the mode are one syscall — no window in
/// which the log is readable by anyone else.
fn create_private_file(path: &Path) -> Result<()> {
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    match opts.open(path) {
        Ok(_) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            set_mode(path, 0o600);
            Ok(())
        }
        Err(e) => Err(e).with_context(|| format!("creating {}", path.display())),
    }
}

/// Set a path's unix mode (best-effort; a no-op off unix).
fn set_mode(path: &Path, mode: u32) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).ok();
    }
    #[cfg(not(unix))]
    {
        let _ = (path, mode);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use library::{FabricKey, NodeIdentity, RosterVersion};
    use proptest::prelude::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    /// A private scratch directory, under `TEST_TMPDIR` when bazel provides one.
    fn temp_dir() -> PathBuf {
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let base = std::env::var_os("TEST_TMPDIR")
            .map(PathBuf::from)
            .unwrap_or_else(std::env::temp_dir);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir = base.join(format!("wires-store-{}-{}", std::process::id(), n));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// The fabric root every fixture topic is derived from.
    fn fabric() -> NodeId {
        NodeIdentity::from_seed([1u8; 32]).node_id()
    }

    /// The topic and the fabric key the fixtures seal under. Fixed bytes, so a
    /// re-seal of the same message is byte-identical (the synthetic IV is keyed
    /// on the fabric key) — which is what makes the idempotence test real.
    fn topic_and_key() -> (TopicId, FabricKey) {
        (
            TopicId::derive(fabric(), "ops"),
            FabricKey::from_bytes([9u8; 32]),
        )
    }

    fn alice() -> NodeIdentity {
        NodeIdentity::from_seed([2u8; 32])
    }

    fn bob() -> NodeIdentity {
        NodeIdentity::from_seed([3u8; 32])
    }

    /// Seal one message into `topic` at `seq`, linked to `prev`.
    fn sealed(
        sender: &NodeIdentity,
        topic: TopicId,
        key: &FabricKey,
        seq: u64,
        prev: MessageHash,
        timestamp: i64,
        text: &str,
    ) -> TopicEnvelope {
        TopicEnvelope::seal(
            sender,
            topic,
            Seq(seq),
            prev,
            RosterVersion(1),
            key,
            timestamp,
            text.as_bytes(),
        )
        .unwrap()
    }

    /// Seal a linked run of `count` messages from `sender`, timestamps
    /// `base_ts + i`, without storing them.
    fn chain(
        sender: &NodeIdentity,
        topic: TopicId,
        key: &FabricKey,
        count: u64,
        base_ts: i64,
    ) -> Vec<TopicEnvelope> {
        let mut prev = MessageHash::ZERO;
        let mut out = Vec::new();
        for i in 0..count {
            let env = sealed(
                sender,
                topic,
                key,
                i,
                prev,
                base_ts + i as i64,
                &format!("message {i}"),
            );
            prev = env.message_hash().unwrap();
            out.push(env);
        }
        out
    }

    /// A store in its own scratch home, plus that home.
    fn store() -> (TopicStore, PathBuf, TopicId, FabricKey) {
        let home = temp_dir();
        let (topic, key) = topic_and_key();
        let store = TopicStore::open(&home, topic).unwrap();
        (store, home, topic, key)
    }

    #[test]
    fn a_fresh_database_reads_as_empty_everywhere() {
        // Deliberately before any write: redb has not created either table yet,
        // so every one of these goes through `missing_is_empty`.
        let (store, _home, _topic, _key) = store();
        let who = alice().node_id();

        assert_eq!(store.chain_state(who).unwrap(), None);
        assert_eq!(store.hash_at(who, Seq::ZERO).unwrap(), None);
        assert!(store.read_after(who, None, 10).unwrap().is_empty());
        assert!(store.senders().unwrap().is_empty());
        assert!(store.hwm_all().unwrap().is_empty());
        assert!(store.read_backfill(10).unwrap().is_empty());
    }

    #[test]
    fn append_inserts_once_and_is_idempotent_thereafter() {
        let (store, _home, topic, key) = store();
        let env = sealed(&alice(), topic, &key, 0, MessageHash::ZERO, 100, "hello");

        assert_eq!(store.append(&env).unwrap(), Appended::Inserted);
        assert_eq!(store.append(&env).unwrap(), Appended::Duplicate);

        // Re-sealing the same message in the same slot is byte-identical, so a
        // republish from a peer that lost its outbox is also a duplicate.
        let resealed = sealed(&alice(), topic, &key, 0, MessageHash::ZERO, 100, "hello");
        assert_eq!(resealed, env);
        assert_eq!(store.append(&resealed).unwrap(), Appended::Duplicate);

        // One message, once.
        assert_eq!(
            store.read_after(alice().node_id(), None, 10).unwrap(),
            [env]
        );
    }

    #[test]
    fn a_different_envelope_in_an_occupied_slot_is_a_fork() {
        let (store, _home, topic, key) = store();
        let held = sealed(&alice(), topic, &key, 0, MessageHash::ZERO, 100, "hello");
        let rival = sealed(&alice(), topic, &key, 0, MessageHash::ZERO, 100, "goodbye");
        store.append(&held).unwrap();

        let err = format!("{:#}", store.append(&rival).unwrap_err());
        assert!(err.contains("fork"), "{err}");
        assert!(err.contains(&alice().node_id().hex()), "{err}");

        // The store keeps what it had; the fork is refused, not resolved.
        assert_eq!(
            store.hash_at(alice().node_id(), Seq::ZERO).unwrap(),
            Some(held.message_hash().unwrap())
        );
        assert_eq!(
            store.read_after(alice().node_id(), None, 10).unwrap(),
            [held]
        );
    }

    #[test]
    fn the_mark_never_lags_the_log_and_hwm_all_agrees_with_chain_state() {
        let (store, _home, topic, key) = store();
        let from_alice = chain(&alice(), topic, &key, 3, 100);
        let from_bob = chain(&bob(), topic, &key, 2, 200);

        // The single write transaction is what makes this hold after *every*
        // append: a committed log entry whose mark did not advance would
        // re-offer the message forever.
        for env in from_alice.iter().chain(from_bob.iter()) {
            assert_eq!(store.append(env).unwrap(), Appended::Inserted);
            assert_eq!(
                store.chain_state(env.sender).unwrap(),
                Some(ChainState::new(env.seq, env.message_hash().unwrap())),
                "mark lagged after appending seq {}",
                env.seq.0
            );
        }

        let all = store.hwm_all().unwrap();
        assert_eq!(all.len(), 2);
        for (sender, state) in &all {
            assert_eq!(store.chain_state(*sender).unwrap().as_ref(), Some(state));
        }
        assert_eq!(all[&alice().node_id()].seq, Seq(2));
        assert_eq!(all[&bob().node_id()].seq, Seq(1));
    }

    #[test]
    fn an_out_of_order_append_leaves_the_mark_behind_the_hole_and_filling_it_heals() {
        // Ingest is supposed to refuse a gap (spec §6) — but the store must not
        // paper over one if it ever sees it, because a mark past a hole hides
        // the hole from replay.
        let (store, _home, topic, key) = store();
        let run = chain(&alice(), topic, &key, 3, 100);

        store.append(&run[0]).unwrap();
        store.append(&run[2]).unwrap();
        assert_eq!(
            store.chain_state(alice().node_id()).unwrap().unwrap().seq,
            Seq(0)
        );

        store.append(&run[1]).unwrap();
        assert_eq!(
            store.chain_state(alice().node_id()).unwrap().unwrap().seq,
            Seq(2)
        );
    }

    #[test]
    fn read_after_windows_the_senders_own_chain() {
        let (store, _home, topic, key) = store();
        let from_alice = chain(&alice(), topic, &key, 5, 100);
        let from_bob = chain(&bob(), topic, &key, 2, 100);
        for env in from_alice.iter().chain(from_bob.iter()) {
            store.append(env).unwrap();
        }
        let who = alice().node_id();

        // From genesis: this sender's chain only, in sequence order.
        assert_eq!(store.read_after(who, None, 10).unwrap(), from_alice);
        // Mid-chain: strictly after the presented mark.
        assert_eq!(
            store.read_after(who, Some(Seq(1)), 10).unwrap(),
            &from_alice[2..]
        );
        // Clamped to `limit`, from the front of the window.
        assert_eq!(store.read_after(who, None, 2).unwrap(), &from_alice[..2]);
        assert_eq!(
            store.read_after(who, Some(Seq(2)), 1).unwrap(),
            &from_alice[3..4]
        );
        // Nothing left, an empty window, and the wire-supplied ceiling.
        assert!(store.read_after(who, Some(Seq(4)), 10).unwrap().is_empty());
        assert!(store.read_after(who, None, 0).unwrap().is_empty());
        assert!(
            store
                .read_after(who, Some(Seq::MAX), 10)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn senders_lists_exactly_the_writers() {
        let (store, _home, topic, key) = store();
        for env in chain(&alice(), topic, &key, 2, 100) {
            store.append(&env).unwrap();
        }
        store
            .append(&chain(&bob(), topic, &key, 1, 100)[0])
            .unwrap();

        let mut expected = vec![alice().node_id(), bob().node_id()];
        expected.sort();
        assert_eq!(store.senders().unwrap(), expected);

        // A node that never published is not a sender.
        let stranger = NodeIdentity::from_seed([4u8; 32]).node_id();
        assert!(!store.senders().unwrap().contains(&stranger));
    }

    #[test]
    fn backfill_merges_by_timestamp_then_sender_then_seq() {
        let (store, _home, topic, key) = store();
        // Alice at t=100 and t=300; Bob at t=100 (a tie with Alice) and t=200.
        let a0 = sealed(&alice(), topic, &key, 0, MessageHash::ZERO, 100, "a0");
        let a1 = sealed(
            &alice(),
            topic,
            &key,
            1,
            a0.message_hash().unwrap(),
            300,
            "a1",
        );
        let b0 = sealed(&bob(), topic, &key, 0, MessageHash::ZERO, 100, "b0");
        let b1 = sealed(
            &bob(),
            topic,
            &key,
            1,
            b0.message_hash().unwrap(),
            200,
            "b1",
        );
        for env in [&a1, &b1, &a0, &b0] {
            store.append(env).unwrap();
        }

        // The tie is broken by sender id, which is what makes two nodes holding
        // the same messages print the same transcript.
        let (tie_first, tie_second) = if alice().node_id() < bob().node_id() {
            (a0.clone(), b0.clone())
        } else {
            (b0.clone(), a0.clone())
        };
        let expected = vec![tie_first, tie_second, b1, a1];
        assert_eq!(store.read_backfill(10).unwrap(), expected);

        // "The newest `limit`", still in display order.
        assert_eq!(store.read_backfill(2).unwrap(), &expected[2..]);
        assert!(store.read_backfill(0).unwrap().is_empty());
    }

    #[test]
    fn a_reopened_store_holds_everything_it_had() {
        let home = temp_dir();
        let (topic, key) = topic_and_key();
        let run = chain(&alice(), topic, &key, 3, 100);

        {
            let store = TopicStore::open(&home, topic).unwrap();
            for env in &run {
                store.append(env).unwrap();
            }
        } // dropped: redb's exclusive lock is released here

        let store = TopicStore::open(&home, topic).unwrap();
        assert_eq!(store.topic(), topic);
        assert_eq!(store.path(), TopicStore::db_path(&home, topic));
        assert_eq!(store.senders().unwrap(), [alice().node_id()]);
        assert_eq!(
            store.chain_state(alice().node_id()).unwrap(),
            Some(ChainState::new(Seq(2), run[2].message_hash().unwrap()))
        );
        assert_eq!(store.read_after(alice().node_id(), None, 10).unwrap(), run);
        assert_eq!(store.read_backfill(10).unwrap(), run);
        // And the messages are still the ones that were sealed, not a re-encode
        // that lost a byte: they still verify and still open.
        assert!(store.read_backfill(1).unwrap()[0].verify().is_ok());
        assert_eq!(
            store.read_backfill(1).unwrap()[0].open(&key).unwrap(),
            b"message 2"
        );
    }

    #[test]
    fn hash_at_hits_stored_slots_and_misses_empty_ones() {
        let (store, _home, topic, key) = store();
        let run = chain(&alice(), topic, &key, 2, 100);
        for env in &run {
            store.append(env).unwrap();
        }

        assert_eq!(
            store.hash_at(alice().node_id(), Seq(1)).unwrap(),
            Some(run[1].message_hash().unwrap())
        );
        // Past the end, and a sender with no chain at all.
        assert_eq!(store.hash_at(alice().node_id(), Seq(2)).unwrap(), None);
        assert_eq!(store.hash_at(bob().node_id(), Seq::ZERO).unwrap(), None);
        // The hash is the chain link, not a hash of the storage encoding.
        assert_eq!(
            store.hash_at(alice().node_id(), Seq(0)).unwrap(),
            Some(run[1].prev_hash)
        );
    }

    #[test]
    fn an_envelope_for_another_topic_is_refused() {
        let (store, _home, _topic, key) = store();
        let elsewhere = TopicId::derive(fabric(), "other");
        let env = sealed(&alice(), elsewhere, &key, 0, MessageHash::ZERO, 100, "hi");

        let err = format!("{:#}", store.append(&env).unwrap_err());
        assert!(err.contains(&elsewhere.hex()), "{err}");
        assert!(store.senders().unwrap().is_empty());
    }

    #[test]
    fn the_log_lives_in_a_private_directory_at_a_private_mode() {
        let home = temp_dir();
        let (topic, key) = topic_and_key();
        let store = TopicStore::open(&home, topic).unwrap();
        store
            .append(&chain(&alice(), topic, &key, 1, 100)[0])
            .unwrap();

        assert_eq!(
            store.path(),
            home.join("topics").join(format!("{}.db", topic.hex()))
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode(&home.join("topics")), 0o700);
            assert_eq!(mode(store.path()), 0o600);
        }
    }

    proptest! {
        /// Log keys round-trip, and order by sender then sequence — the
        /// property the prefix range scan in `read_after` rests on.
        #[test]
        fn log_keys_round_trip_and_sort_by_sender_then_seq(
            sender in proptest::array::uniform32(any::<u8>()),
            a in any::<u64>(),
            b in any::<u64>(),
        ) {
            let sender = NodeId::from_bytes(sender);
            let key = log_key(sender, Seq(a));
            prop_assert_eq!(parse_log_key(&key).unwrap(), (sender, Seq(a)));

            let other = log_key(sender, Seq(b));
            prop_assert_eq!(key.cmp(&other), a.cmp(&b));
        }

        /// High-water-mark values round-trip.
        #[test]
        fn hwm_values_round_trip(
            seq in any::<u64>(),
            hash in proptest::array::uniform32(any::<u8>()),
        ) {
            let state = ChainState::new(Seq(seq), MessageHash::from_bytes(hash));
            prop_assert_eq!(parse_hwm_value(&hwm_value(&state)).unwrap(), state);
        }

        /// Neither parser panics on a record that is not the width it expects —
        /// the database file is an input, not an invariant.
        #[test]
        fn wrong_width_records_error_and_never_panic(
            bytes in proptest::collection::vec(any::<u8>(), 0..96),
        ) {
            prop_assert_eq!(parse_log_key(&bytes).is_ok(), bytes.len() == LOG_KEY_LEN);
            prop_assert_eq!(parse_hwm_value(&bytes).is_ok(), bytes.len() == HWM_VALUE_LEN);
            prop_assert_eq!(parse_sender_key(&bytes).is_ok(), bytes.len() == 32);
        }
    }
}
