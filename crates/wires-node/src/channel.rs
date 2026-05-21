//! Replay a topic log into a `wires_core::channel::ChannelView`. Spec §4.
//!
//! This is the I/O boundary: read ciphertext entries from the on-disk
//! `TopicLog`, decrypt with the relevant epoch key, decode `CanonicalContent`,
//! and drive `wires_core::channel::fold`.

use snafu::ResultExt;
use wires_core::CanonicalContent;
use wires_core::channel::{ChannelView, Event, fold};
use wires_core::wire::{MessageKind, Pubkey, TopicId, WireMessage};
use wires_crypto::decrypt_standard;
use wires_store::{EpochKey, TopicLog};

use crate::error::{ChannelDecryptSnafu, CoreSnafu, Result, StoreSnafu};

/// Replay all decrypted, well-formed entries of `log` into `view`. Public
/// entries (`MessageKind::Public`) carry the canonical content as-is in
/// `ciphertext`; standard-encrypted entries are decrypted with `epoch_key`.
/// Sealed-to entries are skipped — none of the three channel reserved types
/// uses `SealedTo`, so any sealed entry in a channel log is by convention a
/// `__topic.history_grant` from the substrate layer and is not consumed here.
pub fn replay_into(view: &mut ChannelView, log: &TopicLog, epoch_key: &EpochKey) -> Result<()> {
    let entries = log.read_all().context(StoreSnafu)?;
    let mut events: Vec<Event> = Vec::new();
    for msg in entries {
        let content = match msg.kind {
            MessageKind::Public => {
                CanonicalContent::from_canonical_bytes(&msg.ciphertext).context(CoreSnafu)?
            }
            MessageKind::Standard => {
                let aad = aad_for(&msg).context(CoreSnafu)?;
                let pt = decrypt_standard(
                    epoch_key,
                    &msg.topic_id,
                    &msg.sender,
                    msg.seq,
                    &msg.ciphertext,
                    &aad,
                )
                .context(ChannelDecryptSnafu {
                    topic_id_hex: hex::encode(view.topic_id),
                })?;
                CanonicalContent::from_canonical_bytes(&pt).context(CoreSnafu)?
            }
            MessageKind::SealedTo(_) => continue,
        };
        events.push(Event {
            sender: msg.sender,
            content_type: content.type_,
            data: content.data,
        });
    }
    fold(view, events);
    Ok(())
}

fn aad_for(msg: &WireMessage) -> std::result::Result<Vec<u8>, wires_core::CoreError> {
    let mut aad_msg = msg.clone();
    aad_msg.signature = [0u8; 64];
    aad_msg.payload_len = 0;
    aad_msg.ciphertext.clear();
    aad_msg.signing_bytes()
}

/// Detect a DM topic_id against a known set of (root, candidate-other-pubkey)
/// pairs. Returns the sorted participant list on a match, or `None` if `topic_id`
/// is not a DM in this household.
pub fn detect_dm(
    topic_id: &TopicId,
    self_pubkey: &Pubkey,
    root: &Pubkey,
    candidate_others: &[Pubkey],
) -> Option<Vec<Pubkey>> {
    use wires_core::channel::derive::{dm_topic_id, sort_participants};
    for other in candidate_others {
        if other == self_pubkey {
            continue;
        }
        let sorted = sort_participants(vec![*self_pubkey, *other]);
        if dm_topic_id(root, &sorted) == *topic_id {
            return Some(sorted);
        }
    }
    None
}

/// Open a `ChannelView` for `topic_id`. Caller resolves named/DM variant by
/// calling `detect_dm` first if appropriate.
pub fn open_named(topic_id: TopicId, log: &TopicLog, epoch_key: &EpochKey) -> Result<ChannelView> {
    let mut view = ChannelView::empty_named(topic_id);
    replay_into(&mut view, log, epoch_key)?;
    Ok(view)
}

pub fn open_dm(
    topic_id: TopicId,
    participants: Vec<Pubkey>,
    log: &TopicLog,
    epoch_key: &EpochKey,
) -> Result<ChannelView> {
    let mut view = ChannelView::empty_dm(topic_id, participants);
    replay_into(&mut view, log, epoch_key)?;
    Ok(view)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use tempfile::TempDir;

    fn open_log(dir: &std::path::Path, topic_id: [u8; 32]) -> TopicLog {
        let db = wires_store::open_topic_log(dir, &hex::encode(topic_id)).unwrap();
        TopicLog::new(Arc::new(db))
    }

    #[test]
    fn empty_log_yields_empty_view() {
        let tmp = TempDir::new().unwrap();
        let log = open_log(tmp.path(), [1u8; 32]);
        let key: EpochKey = [0u8; 32];
        let view = open_named([1u8; 32], &log, &key).unwrap();
        assert!(view.members.is_empty());
    }
}
