//! How a reader shows a topic: the [`Keyring`] that opens envelopes (healing
//! when a missing key is imported) and the [`Printer`] that renders one line
//! per message on stdout.

use std::collections::{BTreeMap, BTreeSet};
use std::io::Write as _;
use std::sync::Arc;

use library::{FabricKey, NodeId, RosterVersion, TopicEnvelope};

use super::render;
use crate::admin::keystore;
use crate::host::identity;
use crate::now_unix;

/// The keys a tail opens messages with, reloaded when an unknown version shows
/// up.
///
/// Envelopes are storable before their key arrives (spec §4.1), so an unknown
/// `key_version` is not an error: the message is in the log, and the display
/// heals the moment `wires advanced import --fabric-key …` lands — which is why a miss
/// re-reads the keyring before giving up. The warning is **once per version**,
/// because the alternative is one line of stderr per message for as long as the
/// key is missing.
pub(crate) struct Keyring {
    /// Where the keyring is re-read from.
    pub(crate) keystore: Arc<keystore::Keystore>,
    /// Versions this tail holds keys for.
    pub(crate) keys: BTreeMap<RosterVersion, FabricKey>,
    /// Versions already complained about.
    pub(crate) warned: BTreeSet<RosterVersion>,
}

impl Keyring {
    /// Load the installed keyring.
    pub(crate) fn load(keystore: Arc<keystore::Keystore>) -> anyhow::Result<Self> {
        let keys = keystore.read_keyring()?;
        Ok(Self {
            keystore,
            keys,
            warned: BTreeSet::new(),
        })
    }

    /// Decrypt `envelope`, or `None` when this node holds no key for it.
    pub(crate) fn open(&mut self, envelope: &TopicEnvelope) -> Option<Vec<u8>> {
        let version = envelope.key_version;
        if !self.keys.contains_key(&version) {
            // A key imported since startup is the common case here.
            match self.keystore.read_keyring() {
                Ok(keys) => self.keys = keys,
                Err(e) => tracing::warn!("re-reading the keyring: {e:#}"),
            }
        }
        match self.keys.get(&version) {
            Some(key) => match envelope.open(key) {
                Ok(plaintext) => Some(plaintext),
                Err(e) => {
                    tracing::warn!(
                        sender = %envelope.sender.hex(),
                        seq = envelope.seq.0,
                        version = version.0,
                        "stored but undecryptable: {e:#}"
                    );
                    None
                }
            },
            None => {
                if self.warned.insert(version) {
                    eprintln!(
                        "wires watch: no key for roster version {} — those messages are stored but \
                         not shown; run `wires advanced import --fabric-key-file <node-id>.key` for that \
                         commit and they appear",
                        version.0
                    );
                }
                None
            }
        }
    }
}

/// How a tail renders a message on **stdout**.
///
/// stdout is byte-pure message lines and nothing else — every diagnostic in
/// this file goes to stderr or through [`init_logging`] — so a tail can be
/// piped into a file, a pager, or another program without a filter.
pub(crate) struct Printer {
    /// NDJSON instead of the human line.
    pub(crate) json: bool,
    /// Verifies and indexes identity claims (human output only); `None`
    /// prints them as not checked.
    pub(crate) identities: Option<Arc<identity::Identities>>,
}

/// One `--json` output record: the machine-readable form of a message line.
#[derive(serde::Serialize)]
struct JsonLine {
    /// The sender's claimed unix timestamp (informational, spec §4.1).
    pub(crate) ts: i64,
    /// The sender's full node id, hex.
    pub(crate) sender: String,
    /// The message's sequence in that sender's chain.
    pub(crate) seq: u64,
    /// The decrypted UTF-8 text (lossy for non-UTF-8 payloads). Absent when
    /// the text is a [`ChannelRecord`](library::ChannelRecord).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) text: Option<String>,
    /// The parsed record, when the text is one (see [`render`]).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) record: Option<library::ChannelRecord>,
}

impl Printer {
    /// Render one message, or nothing when no key opens it.
    ///
    /// Called only for an envelope whose append reported
    /// [`Appended::Inserted`](crate::channel::store::Appended) — which is what makes
    /// deduplication across live gossip, replay, and restart structural rather
    /// than a remembered set of ids (spec §7).
    ///
    /// An identity claim is verified (and indexed) before its line is
    /// printed; the first claim from an issuer costs one key fetch.
    pub(crate) async fn emit(&self, envelope: &TopicEnvelope, keyring: &mut Keyring) {
        let Some(plaintext) = keyring.open(envelope) else {
            return;
        };
        let text = String::from_utf8_lossy(&plaintext);
        let verdict = match (&self.identities, library::ChannelRecord::parse(&text)) {
            (Some(ids), Some(library::ChannelRecord::Identity(claim))) if !self.json => {
                Some(ids.observe(envelope.sender, &claim, now_unix()).await)
            }
            _ => None,
        };
        let line = self.render_checked(envelope, &text, verdict.as_ref());
        let mut out = std::io::stdout().lock();
        // Piped stdout is block-buffered, so an unflushed tail looks hung.
        if writeln!(out, "{line}").and_then(|()| out.flush()).is_err() {
            // A closed stdout (the pager quit) is not this tail's problem to
            // report on every message.
            tracing::debug!("stdout closed");
        }
    }

    /// [`render_checked`](Self::render_checked) with no identity verdict (an
    /// identity claim renders as not checked).
    #[cfg(test)]
    pub(crate) fn render(&self, envelope: &TopicEnvelope, text: &str) -> String {
        self.render_checked(envelope, text, None)
    }

    /// The exact text of one output line (the testable half of
    /// [`emit`](Self::emit)).
    ///
    /// A message whose text is a [`ChannelRecord`](library::ChannelRecord)
    /// renders through [`render::record_line`] (or, with `--json`, as the
    /// parsed `record` object instead of `text`), with `identity` — this
    /// reader's verdict on it, when it is an identity claim that was checked.
    fn render_checked(
        &self,
        envelope: &TopicEnvelope,
        text: &str,
        identity: Option<&identity::Verdict>,
    ) -> String {
        let record = library::ChannelRecord::parse(text);
        if self.json {
            let line = JsonLine {
                ts: envelope.timestamp,
                sender: envelope.sender.hex(),
                seq: envelope.seq.0,
                text: record.is_none().then(|| text.to_string()),
                record,
            };
            serde_json::to_string(&line).unwrap_or_else(|e| format!("{{\"err\":\"{e}\"}}"))
        } else {
            let body = match &record {
                Some(record) => render::record_line(record, identity),
                None => text.to_string(),
            };
            format!(
                "{} {} {body}",
                format_clock(envelope.timestamp),
                short_id(envelope.sender)
            )
        }
    }
}

/// `HH:MM:SS` **UTC** for a unix timestamp.
///
/// UTC and not local time on purpose: the timestamp is sender-chosen and
/// unverifiable (spec §4.1), so two members reading the same transcript should
/// at least see the same clock. Dateless because a tail is a live feed; the
/// full timestamp is one `--json` away.
fn format_clock(ts: i64) -> String {
    let secs = ts.rem_euclid(86_400);
    format!(
        "{:02}:{:02}:{:02}",
        secs / 3600,
        (secs % 3600) / 60,
        secs % 60
    )
}

/// The first 8 hex characters of a node id — enough to tell members apart in a
/// transcript, short enough to leave room for the message.
fn short_id(node: NodeId) -> String {
    let hex = node.hex();
    hex[..8.min(hex.len())].to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::channel::local::append_local;
    use crate::testutil::{provisioned, temp_dir};

    #[test]
    fn a_message_line_has_a_fixed_shape() {
        let member = provisioned([2u8; 32]);
        let ctx = member.resolve(&member.args()).unwrap();
        let store = member.store();
        // 01:02:05 UTC, fixed, so the line is byte-comparable.
        let envelope = append_local(
            &store,
            &member.node,
            ctx.topic,
            member.version,
            &member.key,
            "ship it",
            3_725,
        )
        .unwrap();

        let printer = Printer {
            json: false,
            identities: None,
        };
        assert_eq!(
            printer.render(&envelope, "ship it"),
            format!("01:02:05 {} ship it", &member.node.node_id().hex()[..8])
        );
        // The clock is dateless and wraps by day; a pre-epoch timestamp still
        // renders rather than panicking.
        assert_eq!(format_clock(0), "00:00:00");
        assert_eq!(format_clock(86_399), "23:59:59");
        assert_eq!(format_clock(86_400 + 61), "00:01:01");
        assert_eq!(format_clock(-1), "23:59:59");
    }

    #[test]
    fn the_json_line_carries_the_documented_fields() {
        let member = provisioned([2u8; 32]);
        let ctx = member.resolve(&member.args()).unwrap();
        let store = member.store();
        let envelope = append_local(
            &store,
            &member.node,
            ctx.topic,
            member.version,
            &member.key,
            "ship it",
            1_700_000_000,
        )
        .unwrap();

        let line = Printer {
            json: true,
            identities: None,
        }
        .render(&envelope, "ship it");
        let value: serde_json::Value = serde_json::from_str(&line).unwrap();
        assert_eq!(value["ts"], 1_700_000_000i64);
        assert_eq!(value["sender"], member.node.node_id().hex());
        assert_eq!(value["seq"], 0);
        assert_eq!(value["text"], "ship it");
        assert!(
            value.get("record").is_none(),
            "plain text carries no record"
        );
        // One line, so NDJSON stays NDJSON.
        assert!(!line.contains('\n'));
    }

    #[test]
    fn a_record_renders_as_its_record_line_and_json_object() {
        let member = provisioned([2u8; 32]);
        let ctx = member.resolve(&member.args()).unwrap();
        let store = member.store();
        let record = library::ChannelRecord::Audit(library::AuditRecord::Denied {
            caller: member.node.node_id(),
            tool: None,
            reason: "roster inclusion rejected: revoked".into(),
            at_ms: 0,
        });
        let text = record.to_text().unwrap();
        let envelope = append_local(
            &store,
            &member.node,
            ctx.topic,
            member.version,
            &member.key,
            &text,
            3_725,
        )
        .unwrap();
        let short = &member.node.node_id().hex()[..8];

        assert_eq!(
            Printer {
                json: false,
                identities: None,
            }
            .render(&envelope, &text),
            format!(
                "01:02:05 {short} ✗ {}… denied: roster inclusion rejected: revoked",
                &short[..4]
            )
        );
        let line = Printer {
            json: true,
            identities: None,
        }
        .render(&envelope, &text);
        let value: serde_json::Value = serde_json::from_str(&line).unwrap();
        assert!(value.get("text").is_none(), "a record replaces the text");
        assert_eq!(value["record"]["type"], "audit");
        assert_eq!(value["record"]["kind"], "denied");
        assert_eq!(
            serde_json::from_value::<library::ChannelRecord>(value["record"].clone()).unwrap(),
            record
        );
    }

    #[test]
    fn an_unknown_key_version_warns_once_and_heals_on_import() {
        let member = provisioned([2u8; 32]);
        let ctx = member.resolve(&member.args()).unwrap();
        let store = member.store();
        let envelope = append_local(
            &store,
            &member.node,
            ctx.topic,
            member.version,
            &member.key,
            "later",
            1,
        )
        .unwrap();

        // A keystore with no keyring at all: the message is stored, not shown.
        let empty = Arc::new(keystore::Keystore::at(temp_dir()));
        let mut keyring = Keyring::load(Arc::clone(&empty)).unwrap();
        assert!(keyring.open(&envelope).is_none());
        assert!(keyring.open(&envelope).is_none());
        assert_eq!(
            keyring.warned.len(),
            1,
            "one warning per version, not per message"
        );

        // The key arrives; the next message opens without a restart.
        empty.save_fabric_key(member.version, &member.key).unwrap();
        assert_eq!(keyring.open(&envelope).unwrap(), b"later");
    }
}
