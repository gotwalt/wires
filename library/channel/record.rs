//! Structured records carried as topic messages.
//!
//! A topic message is UTF-8 text (spec §4.1). Most of it is conversation;
//! some of it is machine-written metadata — call logs from responders
//! ([`AuditRecord`]), IdP identity claims ([`IdentityClaim`]) and the admin's
//! re-keys ([`Rekey`](crate::Rekey)). A
//! [`ChannelRecord`] is that metadata, encoded as a single JSON object tagged
//! with [`RECORD_V1`] so a reader can tell it from a chat line that merely
//! happens to be JSON:
//!
//! ```json
//! {"wires":"record/v1","record":{"type":"audit","kind":"denied",...}}
//! ```
//!
//! The record inherits everything the envelope gives it — signed by the
//! publisher, encrypted to the channel, hash-linked per publisher — so it
//! needs no signature of its own.
//!
//! ```
//! use library::{AuditRecord, ChannelRecord, NodeIdentity};
//! let rec = ChannelRecord::Audit(AuditRecord::Denied {
//!     caller: NodeIdentity::generate().node_id(),
//!     tool: None,
//!     reason: "membership rejected: revoked".into(),
//!     at_ms: 0,
//! });
//! let text = rec.to_text().unwrap();
//! assert_eq!(ChannelRecord::parse(&text), Some(rec));
//! assert_eq!(ChannelRecord::parse("deploying build 41"), None);
//! ```

use serde::{Deserialize, Serialize};

use crate::audit::AuditRecord;
use crate::error::{Error, Result};
use crate::idp::IdentityClaim;
use crate::rekey::Rekey;

/// The `wires` tag value that marks a message as a [`ChannelRecord`].
pub const RECORD_V1: &str = "record/v1";

/// Machine-written metadata on a channel. See the module docs.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ChannelRecord {
    /// A responder's call-log entry.
    Audit(AuditRecord),
    /// A node's IdP identity claim.
    Identity(IdentityClaim),
    /// A roster commit's credentials for its members, published by the
    /// admin so members adopt the new head, proof and fabric key without a
    /// manual import. Self-verifying: see [`crate::rekey`].
    Rekey(Rekey),
}

#[derive(Serialize, Deserialize)]
struct Tagged<T> {
    wires: String,
    record: T,
}

impl ChannelRecord {
    /// Encode as the one-line message text to publish.
    pub fn to_text(&self) -> Result<String> {
        serde_json::to_string(&Tagged {
            wires: RECORD_V1.to_string(),
            record: self,
        })
        .map_err(Error::Encode)
    }

    /// Parse a message's text. `None` means "not a record" — ordinary
    /// conversation, a record of an unknown version, or a malformed one; the
    /// caller renders it as plain text either way.
    pub fn parse(text: &str) -> Option<Self> {
        let tagged: Tagged<ChannelRecord> = serde_json::from_str(text).ok()?;
        (tagged.wires == RECORD_V1).then_some(tagged.record)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::{CallId, OutputDigest};
    use crate::identity::NodeIdentity;
    use crate::idp::IdToken;
    use crate::invoke::{Argv, ToolName};

    fn samples() -> Vec<ChannelRecord> {
        let node = NodeIdentity::generate().node_id();
        let call = CallId::generate();
        vec![
            ChannelRecord::Audit(AuditRecord::Started {
                call,
                caller: node,
                principal: None,
                tool: ToolName::new("db_query").unwrap(),
                argv: Argv::new(vec!["select 1".into()]).unwrap(),
                roster_version: Some(3),
                at_ms: 1,
            }),
            ChannelRecord::Audit(AuditRecord::Finished {
                call,
                exit: 0,
                duration_ms: 12,
                stdout_bytes: 2,
                stderr_bytes: 0,
                stdout_digest: OutputDigest::from_hash(blake3::hash(b"1\n")),
                stdin_bytes: 8,
                stdin_digest: OutputDigest::from_hash(blake3::hash(b"select 1")),
                stdin_head: Some("select 1".into()),
            }),
            ChannelRecord::Identity(IdentityClaim {
                node,
                id_token: IdToken::new("a.b.c"),
            }),
            ChannelRecord::Rekey(rekey_sample()),
        ]
    }

    /// A one-member commit as a re-key record.
    fn rekey_sample() -> Rekey {
        use crate::fabric_key::{FabricKey, SealedFabricKey};
        use crate::rekey::RekeyEntry;
        let root = NodeIdentity::from_seed([1u8; 32]);
        let member = NodeIdentity::from_seed([2u8; 32]).node_id();
        let mut roster = crate::roster::Roster::new(root.node_id());
        roster.insert(member);
        let (head, proofs) = roster.commit(&root, 0, i64::MAX).unwrap();
        let key = SealedFabricKey::seal(&root, member, head.version, &FabricKey::generate()).unwrap();
        Rekey::new(
            head,
            vec![RekeyEntry {
                proof: proofs[0].1.clone(),
                key,
            }],
        )
    }

    #[test]
    fn records_round_trip_through_text() {
        for rec in samples() {
            let text = rec.to_text().unwrap();
            assert!(!text.contains('\n'), "a record is one line");
            assert_eq!(ChannelRecord::parse(&text), Some(rec));
        }
    }

    #[test]
    fn plain_text_and_foreign_json_are_not_records() {
        for text in [
            "hello",
            "{}",
            r#"{"wires":"record/v9","record":{}}"#,
            r#"{"a":1}"#,
        ] {
            assert_eq!(ChannelRecord::parse(text), None, "{text}");
        }
    }
}
