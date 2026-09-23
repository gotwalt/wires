//! The host's own call log on disk (card 26a): every [`AuditRecord`] the host
//! produces, as a signed, hash-linked [`LogEntry`] (see [`library::call_log`]).
//!
//! # Storage: one append-only JSON-lines file
//!
//! `$WIRES_HOME/call-log.jsonl` holds one entry per line, oldest first.
//! Appending writes the line and `fsync`s (`sync_data`) before the entry
//! counts as logged. Chosen over redb because:
//!
//! - the data *is* an append-only sequence read front to back (a subscriber
//!   asks for "everything after seq N"), which a file does natively;
//! - the entries are self-verifying, so the store needs no transactional
//!   integrity of its own: [`CallLog::open`] re-verifies the whole chain, and
//!   a flipped byte anywhere is caught there (and by any reader);
//! - it is inspectable with `jq`, and adds no dependency to a crate whose
//!   dependency list is being cut down (card 25).
//!
//! A torn final line (a crash mid-append) is truncated on open with a warning:
//! it was never fsync'd, so it was never logged. Anything else that doesn't
//! parse or verify refuses to open, naming the file, rather than silently
//! appending to a history that no longer verifies.
//!
//! **Retention** drops whole entries older than [`Retention`] from the front,
//! by rewriting the kept suffix to a temp file and renaming it over the log.
//! It runs on open and whenever the oldest held entry ages out, so there is
//! no timer. The newest entry is always kept, so sequence numbers never
//! restart (not even across a restart after a quiet month): a pruned log
//! begins at its first kept `seq`.
//!
//! # Where records come from
//!
//! [`start`] hands `serve` the [`AuditSink`] every session and push writes
//! to, and runs a [`tee`] that appends each record to this log (always),
//! offers the signed entry to the OTLP [`Exporter`] (when `host.json` has
//! `audit.otlp`), and passes the record on to the channel publisher (while the
//! host still has a channel; card 27 removes that).

use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use library::{AuditRecord, ChainPoint, LogEntry, NodeIdentity, Retention, verify_chain};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use crate::host::audit::{AUDIT_QUEUE, now_ms};
use crate::host::otlp::Exporter;
use crate::host::transport::AuditSink;

/// The log's file name under the wires home.
pub const LOG_FILE: &str = "call-log.jsonl";

/// A host's call log, open for appending. See the module docs.
pub struct CallLog {
    /// The JSON-lines file.
    path: PathBuf,
    /// The file, opened for appending.
    file: File,
    /// The host key every entry is signed with.
    host: NodeIdentity,
    /// How long entries are kept.
    retention: Retention,
    /// The last entry appended, if any (survives pruning).
    tip: Option<ChainPoint>,
    /// `at_ms` of the oldest entry held, if any.
    oldest_ms: Option<i64>,
}

impl std::fmt::Debug for CallLog {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CallLog")
            .field("path", &self.path)
            .field("tip", &self.tip)
            .finish_non_exhaustive()
    }
}

impl CallLog {
    /// Open (or create) the log at `path` for `host`, verify every entry in
    /// it, and prune what `retention` no longer keeps.
    ///
    /// Fails when an entry (other than a torn last line) doesn't parse, or
    /// the chain doesn't verify as `host`'s — see the module docs.
    pub fn open(path: &Path, host: NodeIdentity, retention: Retention) -> Result<Self> {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
        }
        let entries = read_repairing(path)?;
        let tip = verify_chain(host.node_id(), None, &entries).with_context(|| {
            format!(
                "the call log {} does not verify; move it aside to start a new one",
                path.display()
            )
        })?;
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .with_context(|| format!("opening {}", path.display()))?;
        let mut log = Self {
            path: path.to_path_buf(),
            file,
            host,
            retention,
            tip,
            oldest_ms: entries.first().map(|e| e.at_ms),
        };
        log.prune(now_ms())?;
        Ok(log)
    }

    /// The last entry appended (`None` for a log that never had one).
    pub fn tip(&self) -> Option<ChainPoint> {
        self.tip
    }

    /// Where the log lives.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Sign `record` as the next entry, logged now, and append it durably.
    pub fn append(&mut self, record: AuditRecord) -> Result<LogEntry> {
        self.append_at(now_ms(), record)
    }

    /// [`append`](Self::append) with an explicit log time (tests, and
    /// retention runs against the same clock).
    pub fn append_at(&mut self, at_ms: i64, record: AuditRecord) -> Result<LogEntry> {
        if self
            .oldest_ms
            .is_some_and(|t| !self.retention.keeps(at_ms, t))
        {
            self.prune(at_ms)?;
        }
        let entry = LogEntry::next(&self.host, self.tip, at_ms, record)?;
        let mut line = serde_json::to_vec(&entry)?;
        line.push(b'\n');
        self.file
            .write_all(&line)
            .and_then(|()| self.file.sync_data())
            .with_context(|| format!("appending to {}", self.path.display()))?;
        self.tip = Some(entry.point()?);
        self.oldest_ms.get_or_insert(at_ms);
        Ok(entry)
    }

    /// Drop the entries `retention` no longer keeps at `now_ms` from the
    /// front of the log. Returns how many were dropped.
    pub fn prune(&mut self, now_ms: i64) -> Result<usize> {
        if self
            .oldest_ms
            .is_none_or(|t| self.retention.keeps(now_ms, t))
        {
            return Ok(0);
        }
        let entries = read(&self.path)?;
        let cut = entries
            .iter()
            .position(|e| self.retention.keeps(now_ms, e.at_ms))
            .unwrap_or(entries.len())
            // The newest entry always stays: it is what the next append (after
            // a restart, too) links to, so the sequence never restarts.
            .min(entries.len().saturating_sub(1));
        if cut == 0 {
            self.oldest_ms = entries.first().map(|e| e.at_ms);
            return Ok(0);
        }
        let tmp = self.path.with_extension("jsonl.tmp");
        {
            let mut out =
                File::create(&tmp).with_context(|| format!("creating {}", tmp.display()))?;
            for e in &entries[cut..] {
                let mut line = serde_json::to_vec(e)?;
                line.push(b'\n');
                out.write_all(&line)?;
            }
            out.sync_all()?;
        }
        std::fs::rename(&tmp, &self.path)
            .with_context(|| format!("replacing {}", self.path.display()))?;
        if let Some(dir) = self.path.parent()
            && let Ok(d) = File::open(dir)
        {
            let _ = d.sync_all();
        }
        self.file = OpenOptions::new().append(true).open(&self.path)?;
        self.oldest_ms = entries.get(cut).map(|e| e.at_ms);
        tracing::info!(dropped = cut, "call log: pruned entries past retention");
        Ok(cut)
    }
}

/// Read every entry in the log at `path` (none when it doesn't exist),
/// without verifying them. A reader verifies with [`verify_chain`].
pub fn read(path: &Path) -> Result<Vec<LogEntry>> {
    let file = match File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e).with_context(|| format!("reading {}", path.display())),
    };
    let mut out = Vec::new();
    for (i, line) in BufReader::new(file).lines().enumerate() {
        let line = line?;
        let entry = serde_json::from_str(&line)
            .with_context(|| format!("{} line {} is not a log entry", path.display(), i + 1))?;
        out.push(entry);
    }
    Ok(out)
}

/// [`read`], but first truncate a torn final line (bytes after the last
/// newline: an append that never reached its `fsync`).
fn read_repairing(path: &Path) -> Result<Vec<LogEntry>> {
    if let Ok(mut file) = OpenOptions::new().read(true).write(true).open(path) {
        let mut bytes = Vec::new();
        std::io::Read::read_to_end(&mut file, &mut bytes)?;
        let keep = bytes.iter().rposition(|b| *b == b'\n').map_or(0, |i| i + 1);
        if keep < bytes.len() {
            tracing::warn!(
                path = %path.display(),
                bytes = bytes.len() - keep,
                "call log: dropping a torn final line"
            );
            file.set_len(keep as u64)?;
            file.seek(SeekFrom::End(0))?;
            file.sync_all()?;
        }
    }
    let entries = read(path)?;
    if entries.windows(2).any(|w| w[1].seq <= w[0].seq) {
        bail!("{} holds entries out of order", path.display());
    }
    Ok(entries)
}

/// Build the host's audit path: a sink for sessions and pushes, a [`tee`]
/// running on a blocking thread, and — when `channel` is set — the receiver
/// the channel publisher drains (as before card 26a).
pub fn start(
    log: CallLog,
    exporter: Option<Exporter>,
    channel: bool,
) -> (
    AuditSink,
    Option<mpsc::Receiver<AuditRecord>>,
    JoinHandle<()>,
) {
    tracing::info!(
        path = %log.path().display(),
        next = log.tip().map_or(0, |t| t.seq.0 + 1),
        "call log open"
    );
    let (sink, records) = AuditSink::channel(AUDIT_QUEUE);
    let (to_channel, from_tee) = if channel {
        let (tx, rx) = mpsc::channel(AUDIT_QUEUE);
        (Some(tx), Some(rx))
    } else {
        (None, None)
    };
    let tee = tokio::task::spawn_blocking(move || tee(records, log, exporter, to_channel));
    (sink, from_tee, tee)
}

/// Drain `records`: append each to `log`, offer the signed entry to
/// `exporter`, and pass the record on to `channel`. Returns when `records`
/// closes.
///
/// Blocking (it `fsync`s): run it on a blocking thread. Never waits on the
/// exporter or the channel — both are offered with `try_send` and a full
/// queue drops with a warning — so a slow collector or a stuck channel can't
/// stall the log. A failed append is logged and the record still flows on.
pub fn tee(
    mut records: mpsc::Receiver<AuditRecord>,
    mut log: CallLog,
    exporter: Option<Exporter>,
    mut channel: Option<mpsc::Sender<AuditRecord>>,
) {
    while let Some(record) = records.blocking_recv() {
        match log.append(record.clone()) {
            Ok(entry) => {
                if let Some(x) = &exporter {
                    x.export(entry);
                }
            }
            Err(e) => tracing::warn!("call log: record not logged: {e:#}"),
        }
        if let Some(tx) = &channel {
            match tx.try_send(record) {
                Ok(()) => {}
                Err(mpsc::error::TrySendError::Full(_)) => {
                    tracing::warn!("audit record not published: the channel queue is full")
                }
                Err(mpsc::error::TrySendError::Closed(_)) => {
                    tracing::warn!("the channel publisher is gone; records stay in the call log");
                    channel = None;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use library::{ChainBreak, LogSeq};
    use proptest::prelude::*;
    use std::time::Duration;

    fn host() -> NodeIdentity {
        NodeIdentity::from_seed([6u8; 32])
    }

    fn denied(n: i64) -> AuditRecord {
        AuditRecord::Denied {
            caller: NodeIdentity::from_seed([7u8; 32]).node_id(),
            tool: None,
            reason: format!("no {n}"),
            at_ms: n,
        }
    }

    fn open(path: &Path) -> CallLog {
        CallLog::open(path, host(), Retention::default()).unwrap()
    }

    fn verify(path: &Path) -> std::result::Result<Option<ChainPoint>, ChainBreak> {
        verify_chain(host().node_id(), None, &read(path).unwrap())
    }

    #[test]
    fn appends_survive_a_reopen_and_continue_the_chain() {
        let dir = crate::testutil::temp_dir();
        let path = dir.join(LOG_FILE);
        let now = now_ms();
        {
            let mut log = open(&path);
            assert_eq!(log.tip(), None);
            log.append_at(now, denied(1)).unwrap();
            log.append_at(now, denied(2)).unwrap();
        }
        let mut log = open(&path);
        assert_eq!(log.tip().unwrap().seq, LogSeq(1));
        let third = log.append_at(now, denied(3)).unwrap();
        assert_eq!(third.seq, LogSeq(2));
        let entries = read(&path).unwrap();
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[2], third);
        assert_eq!(verify(&path).unwrap(), log.tip());
        assert_eq!(entries[0].record, denied(1));
    }

    /// The card's acceptance, at the store: flip a byte in the file and the
    /// log no longer opens (and a reader's verification says where).
    #[test]
    fn a_flipped_byte_in_the_store_is_detected() {
        let dir = crate::testutil::temp_dir();
        let path = dir.join(LOG_FILE);
        {
            let mut log = open(&path);
            for n in 0..3 {
                log.append_at(now_ms(), denied(n)).unwrap();
            }
        }
        let text = std::fs::read_to_string(&path).unwrap();
        let tampered = text.replacen("no 1", "no 7", 1);
        assert_ne!(text, tampered);
        std::fs::write(&path, tampered).unwrap();
        assert_eq!(
            verify(&path),
            Err(ChainBreak::BadSignature { seq: LogSeq(1) })
        );
        let e = format!(
            "{:#}",
            CallLog::open(&path, host(), Retention::default()).unwrap_err()
        );
        assert!(e.contains("does not verify"), "{e}");
    }

    #[test]
    fn a_deleted_line_is_a_gap() {
        let dir = crate::testutil::temp_dir();
        let path = dir.join(LOG_FILE);
        {
            let mut log = open(&path);
            for n in 0..3 {
                log.append_at(now_ms(), denied(n)).unwrap();
            }
        }
        let text = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        std::fs::write(&path, format!("{}\n{}\n", lines[0], lines[2])).unwrap();
        assert!(matches!(verify(&path), Err(ChainBreak::Gap { .. })));
        assert!(CallLog::open(&path, host(), Retention::default()).is_err());
    }

    #[test]
    fn a_torn_last_line_is_dropped_on_open() {
        let dir = crate::testutil::temp_dir();
        let path = dir.join(LOG_FILE);
        {
            let mut log = open(&path);
            log.append_at(now_ms(), denied(1)).unwrap();
        }
        let mut f = OpenOptions::new().append(true).open(&path).unwrap();
        f.write_all(br#"{"v":1,"host":"ab"#).unwrap();
        drop(f);
        let mut log = open(&path);
        assert_eq!(log.tip().unwrap().seq, LogSeq(0));
        log.append_at(now_ms(), denied(2)).unwrap();
        assert_eq!(verify(&path).unwrap().unwrap().seq, LogSeq(1));
    }

    #[test]
    fn another_hosts_log_does_not_open() {
        let dir = crate::testutil::temp_dir();
        let path = dir.join(LOG_FILE);
        open(&path).append_at(now_ms(), denied(1)).unwrap();
        let other = NodeIdentity::from_seed([8u8; 32]);
        assert!(CallLog::open(&path, other, Retention::default()).is_err());
    }

    #[test]
    fn retention_prunes_the_front_and_keeps_the_sequence() {
        let dir = crate::testutil::temp_dir();
        let path = dir.join(LOG_FILE);
        let retention = Retention::new(Duration::from_millis(100));
        let mut log = CallLog::open(&path, host(), retention).unwrap();
        log.append_at(1_000, denied(0)).unwrap();
        log.append_at(1_050, denied(1)).unwrap();
        // At 1_120 entry 0 has aged out; appending prunes it first.
        let e = log.append_at(1_120, denied(2)).unwrap();
        assert_eq!(e.seq, LogSeq(2));
        let held = read(&path).unwrap();
        assert_eq!(
            held.iter().map(|e| e.seq).collect::<Vec<_>>(),
            [LogSeq(1), LogSeq(2)]
        );
        assert_eq!(verify(&path).unwrap(), log.tip());
        // Everything aged out: all but the newest entry go.
        assert_eq!(log.prune(10_000).unwrap(), 1);
        assert_eq!(read(&path).unwrap().len(), 1);
        assert_eq!(log.prune(10_000).unwrap(), 0);
        drop(log);
        // The sequence carries on, across a reopen.
        let mut log = CallLog::open(&path, host(), retention).unwrap();
        assert_eq!(log.append_at(10_000, denied(3)).unwrap().seq, LogSeq(3));
        assert_eq!(verify(&path).unwrap(), log.tip());
    }

    /// The tee logs every record, offers each entry to the exporter, and
    /// passes every record to the channel in order.
    #[tokio::test]
    async fn the_tee_logs_exports_and_forwards() {
        let dir = crate::testutil::temp_dir();
        let path = dir.join(LOG_FILE);
        let (exporter, mut exported) = Exporter::channel(16);
        let (sink, channel, tee) = start(open(&path), Some(exporter), true);
        let mut channel = channel.unwrap();
        for n in 0..3 {
            sink.record(denied(n));
        }
        drop(sink);
        tee.await.unwrap();
        let mut forwarded = Vec::new();
        while let Some(r) = channel.recv().await {
            forwarded.push(r);
        }
        assert_eq!(forwarded, [denied(0), denied(1), denied(2)]);
        let logged = read(&path).unwrap();
        assert_eq!(logged.len(), 3);
        for e in &logged {
            assert_eq!(exported.recv().await.as_ref(), Some(e));
        }
        assert_eq!(verify(&path).unwrap().unwrap().seq, LogSeq(2));
    }

    /// Without a channel the tee still logs; nothing is forwarded.
    #[tokio::test]
    async fn the_log_is_kept_without_a_channel_or_exporter() {
        let dir = crate::testutil::temp_dir();
        let path = dir.join(LOG_FILE);
        let (sink, channel, tee) = start(open(&path), None, false);
        assert!(channel.is_none());
        sink.record(denied(1));
        drop(sink);
        tee.await.unwrap();
        assert_eq!(read(&path).unwrap().len(), 1);
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(16))]
        /// Any number of appends across any number of reopens yields one
        /// verifying chain with dense sequence numbers.
        #[test]
        fn reopening_never_breaks_the_chain(batches in proptest::collection::vec(0usize..4, 1..5)) {
            let dir = crate::testutil::temp_dir();
            let path = dir.join(LOG_FILE);
            let mut n = 0i64;
            for batch in batches {
                let mut log = open(&path);
                for _ in 0..batch {
                    log.append_at(now_ms(), denied(n)).unwrap();
                    n += 1;
                }
            }
            let entries = read(&path).unwrap();
            prop_assert_eq!(entries.len() as i64, n);
            for (i, e) in entries.iter().enumerate() {
                prop_assert_eq!(e.seq, LogSeq(i as u64));
                prop_assert_eq!(e.host, host().node_id());
            }
            prop_assert!(verify(&path).is_ok());
        }
    }
}
