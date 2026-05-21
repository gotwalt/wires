//! Replay a topic log into a `wires_core::channel::ChannelView`. Spec §4.
//!
//! This is the I/O boundary: read ciphertext entries from the on-disk
//! `TopicLog`, decrypt with the relevant epoch key, decode `CanonicalContent`,
//! and drive `wires_core::channel::fold`. Also houses shared higher-level
//! channel helpers (`allocate_named`, `find_cap_for`, `publish_create_and_meta`,
//! `invite_member`, `dm_open`) used by both `wires-cli` and `wires-mcp`.

use rand_core::{OsRng, RngCore};
use snafu::ResultExt;
use wires_core::CanonicalContent;
use wires_core::CapId;
use wires_core::cap::Right;
use wires_core::channel::ChannelView;
use wires_core::channel::derive::{dm_epoch_key, dm_topic_id, sort_participants};
use wires_core::channel::schemas::{
    ChannelCreate, ChannelInvite, ChannelMemberMeta, TYPE_CREATE, TYPE_INVITE, TYPE_MEMBER_META,
};
use wires_core::channel::types::MemberKind;
use wires_core::channel::{Event, fold};
use wires_core::wire::{MessageKind, Pubkey, TopicId, WireMessage};
use wires_crypto::decrypt_standard;
use wires_store::{EpochKey, TopicLog};

use crate::error::{ChannelDecryptSnafu, CoreSnafu, Result, SerdeSnafu, StoreSnafu};
use crate::node::Node;
use crate::publish::{KeyingMaterial, PublishParams, build_message};
use crate::topic_names::upsert_entries as upsert_topic_names;

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
/// is not a DM in this fabric.
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

/// Allocate a fresh `(topic_id, epoch_key)` pair for a new named channel and
/// install the epoch key on `node`. Returns the new topic_id; the caller is
/// responsible for adding it to `topic_names.json` and minting/finding a cap.
pub fn allocate_named(node: &Node) -> Result<(TopicId, EpochKey)> {
    let mut topic_id = [0u8; 32];
    OsRng.fill_bytes(&mut topic_id);
    let mut key = [0u8; 32];
    OsRng.fill_bytes(&mut key);
    node.install_epoch_key(topic_id, 0, key)?;
    Ok((topic_id, key))
}

/// Return the first non-revoked cap held by `node` that covers `topic_name`
/// for `right`. Returns `None` if no such cap exists. (Lifted from
/// `wires-cli/src/cmd/publish_helpers.rs` so `wires-mcp` can use it too.)
pub fn find_cap_for(node: &Node, topic_name: &str, right: Right) -> Option<CapId> {
    let caps = node.caps.all().ok()?;
    for (cap_id, entry) in caps {
        if entry.revoked {
            continue;
        }
        if entry.cap.allows(topic_name, right).is_ok() {
            return Some(cap_id);
        }
    }
    None
}

/// Publish a `MessageKind::Public` envelope containing `content` to `topic_id`.
/// Shared by `wires-cli` and `wires-mcp` channel/me/dm flows.
pub fn publish_public(
    node: &Node,
    topic_id: TopicId,
    cap_id: CapId,
    content_type: &str,
    text: &str,
    content: serde_json::Value,
    timestamp: i64,
) -> Result<()> {
    let canonical = CanonicalContent::new(content_type, text).with_data(content);
    let (seq, prev_hash) = node.next_seq_and_prev_hash(&topic_id)?;
    let params = PublishParams {
        topic_id,
        sender_sk: &node.ed_sk,
        cap_id,
        kind: MessageKind::Public,
        content: canonical,
        epoch: 0,
        seq,
        prev_hash,
        timestamp,
        keying: KeyingMaterial::Public,
    };
    let msg = build_message(&params)?;
    node.append_local(&msg)?;
    Ok(())
}

/// Publish `__channel.create` and the publisher's `__channel.member_meta` (both
/// `MessageKind::Public`). Used by `wires channel create` and `wires_create_channel`.
#[allow(clippy::too_many_arguments)]
pub fn publish_create_and_meta(
    node: &Node,
    topic_id: TopicId,
    topic_name: &str,
    cap_id: CapId,
    description: Option<&str>,
    display_name: &str,
    kind: MemberKind,
    now: i64,
) -> Result<()> {
    let create = ChannelCreate {
        name: topic_name.to_string(),
        description: description.map(str::to_string),
        created_at: now,
    };
    let value = serde_json::to_value(&create).context(SerdeSnafu)?;
    publish_public(
        node,
        topic_id,
        cap_id,
        TYPE_CREATE,
        &format!("created channel {topic_name}"),
        value,
        now,
    )?;

    let meta = ChannelMemberMeta {
        kind,
        display_name: display_name.to_string(),
        description: None,
        asserted_at: now,
    };
    let value = serde_json::to_value(&meta).context(SerdeSnafu)?;
    publish_public(
        node,
        topic_id,
        cap_id,
        TYPE_MEMBER_META,
        &format!("member {display_name}"),
        value,
        now,
    )?;
    Ok(())
}

/// Invite-flow helper: publishes a sealed `__topic.history_grant` to `invitee`
/// followed by a public `__channel.invite`. Order matches the CLI: grant first
/// so the invitee can decrypt history once they fold the invite.
pub fn invite_member(
    node: &Node,
    topic_id: TopicId,
    cap_id: CapId,
    invitee: Pubkey,
    epoch_key: &EpochKey,
    now: i64,
) -> Result<()> {
    let grant_canonical =
        CanonicalContent::new("__topic.history_grant", "epoch key for new member").with_data(
            serde_json::json!({
                "epoch": 0,
                "key_hex": hex::encode(epoch_key),
            }),
        );
    let (seq, prev_hash) = node.next_seq_and_prev_hash(&topic_id)?;
    let grant_params = PublishParams {
        topic_id,
        sender_sk: &node.ed_sk,
        cap_id,
        kind: MessageKind::SealedTo(invitee),
        content: grant_canonical,
        epoch: 0,
        seq,
        prev_hash,
        timestamp: now,
        keying: KeyingMaterial::SealedRecipient(&invitee),
    };
    let grant_msg = build_message(&grant_params)?;
    node.append_local(&grant_msg)?;

    let invite_value = serde_json::to_value(&ChannelInvite {
        agent: invitee,
        invited_at: now,
    })
    .context(SerdeSnafu)?;
    publish_public(
        node,
        topic_id,
        cap_id,
        TYPE_INVITE,
        &format!("invited {}", hex::encode(invitee)),
        invite_value,
        now,
    )?;
    Ok(())
}

/// Result of `dm_open`. Carries the derived topic_id, sorted participants, and
/// the epoch key the caller may want to use for follow-up sends.
pub struct DmOpened {
    pub topic_id: TopicId,
    pub topic_name: String,
    pub participants: Vec<Pubkey>,
    pub epoch_key: EpochKey,
}

/// Shared DM-open helper: derive the topic_id + epoch key for a DM between
/// `node` and `other`, install the key, register the topic name, and (if not
/// yet on-log) publish this node's `__channel.member_meta`. Returns the
/// derived material so callers can chain a follow-up message send.
///
/// Callers are responsible for upserting the dm_roster entry beforehand and
/// for publishing any first message they want to send. This helper does NOT
/// look up `other`'s x25519 from disk — pass it in directly.
#[allow(clippy::too_many_arguments)]
pub fn dm_open(
    node: &Node,
    data_dir: &std::path::Path,
    root: &Pubkey,
    other: Pubkey,
    other_x25519: [u8; 32],
    display_name: &str,
    kind: MemberKind,
    now: i64,
) -> Result<DmOpened> {
    let self_pk = node.ed_sk.verifying_key().to_bytes();
    let participants = sort_participants(vec![self_pk, other]);
    let topic_id = dm_topic_id(root, &participants);

    let self_x_sk_bytes = node.x_sk.to_bytes();
    let epoch_key = dm_epoch_key(&self_x_sk_bytes, &other_x25519, root, &participants);

    node.install_epoch_key(topic_id, 0, epoch_key)?;
    let topic_name = wires_core::channel::derive::dm_topic_name(&topic_id);
    upsert_topic_names(data_dir, [(topic_name.clone(), topic_id)])?;

    // Best-effort publish of our member_meta if we haven't already.
    let cap_id = find_cap_for(node, &topic_name, Right::Write);
    if let Some(cap_id) = cap_id {
        let log = node.open_topic_log(&topic_id)?;
        let view = open_dm(topic_id, participants.clone(), &log, &epoch_key)?;
        if !view.members.contains_key(&self_pk) {
            let meta = ChannelMemberMeta {
                kind,
                display_name: display_name.to_string(),
                description: None,
                asserted_at: now,
            };
            let value = serde_json::to_value(&meta).context(SerdeSnafu)?;
            publish_public(
                node,
                topic_id,
                cap_id,
                TYPE_MEMBER_META,
                &format!("member {display_name}"),
                value,
                now,
            )?;
        }
    }

    Ok(DmOpened {
        topic_id,
        topic_name,
        participants,
        epoch_key,
    })
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
