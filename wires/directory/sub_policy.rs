//! A host's `policy` subscription (card 36c), the directory side.
//!
//! A host subscribes with the version it holds (`have`; 0: none). The
//! directory sends, on one long-lived stream:
//!
//! - first, what brings it to the newest head ([`since`]): nothing but a
//!   `fresh` beat when `have` is the newest; a `policy_update` (the new head,
//!   the items changed and the keys removed, from
//!   [`SignedPolicy::update_from`] against the head at `have` kept in
//!   `directory.redb`) when `have` is one of the [`KEEP_HEADS`](super::db::KEEP_HEADS)
//!   kept heads; the whole `policy` otherwise (`have` 0, too old, or unknown);
//! - then a `policy_update` for every head the directory adopts (a publish,
//!   or a replica catching up), each with its `Fresh`;
//! - and a `fresh` beat every `settings.beat_secs` in between.
//!
//! A subscriber that can't apply an update subscribes anew with `have: 0`.
//! The stream ends with `denied` when this node stops being a directory
//! (it can no longer vouch), and the host fails over to another.
//!
//! Subscribers following the same head get the same bytes: each frame is
//! encoded once per `(have, head, Fresh)` and shared ([`FrameCache`]), so a
//! publish to a directory with a thousand hosts reads the older policy from
//! the store and diffs it once, not a thousand times.
//!
//! `policy {have}` on `wires/directory/1` answers the same way
//! ([`since`]), for a host's one-shot fetch.

use std::sync::{Arc, Mutex};

use anyhow::Result;
use iroh::endpoint::{Connection, SendStream};
use library::{Fresh, NodeId, PolicyUpdate, StateVersion, SubFrame};

use super::node::{Current, Directory};
use super::wire;

/// What brings a holder of `have` to a directory's newest head.
#[derive(Clone, Debug, PartialEq, Eq)]
#[allow(clippy::large_enum_variant)]
pub(crate) enum Since {
    /// `have` is the newest (or newer than the directory's): nothing to send
    /// but freshness.
    Current,
    /// The delta from the kept head at `have`.
    Update(PolicyUpdate),
    /// The whole policy: `have` is 0, older than every kept head, or not a
    /// head the directory kept.
    Whole,
}

/// What `c` (the directory's newest) is to a holder of `have`. See the
/// module docs. A store that can't be read gives [`Since::Whole`].
pub(crate) fn since(dir: &Directory, c: &Current, have: StateVersion) -> Since {
    if have >= c.held.version() {
        return Since::Current;
    }
    if have.0 == 0 {
        return Since::Whole;
    }
    match dir.policy_at(have) {
        Ok(Some(older)) => Since::Update(c.held.signed.update_from(&older)),
        Ok(None) => Since::Whole,
        Err(e) => {
            tracing::warn!(
                have = have.0,
                "directory: reading a kept head failed: {e:#}"
            );
            Since::Whole
        }
    }
}

/// The frame a subscriber at `sent` gets for `c` and its `fresh`, and the
/// version it then holds; `None` when it holds a newer head than the
/// directory (it waits for the directory to catch up).
fn next_frame(
    dir: &Directory,
    c: &Current,
    fresh: &Fresh,
    sent: StateVersion,
) -> Option<(SubFrame, StateVersion)> {
    let version = c.held.version();
    if sent > version {
        return None;
    }
    let frame = match since(dir, c, sent) {
        Since::Current => SubFrame::Fresh {
            fresh: fresh.clone(),
        },
        Since::Update(update) => SubFrame::PolicyUpdate {
            update,
            fresh: fresh.clone(),
        },
        Since::Whole => SubFrame::Policy {
            policy: c.held.signed.clone(),
            fresh: fresh.clone(),
        },
    };
    Some((frame, version))
}

/// The encoded frames subscribers share: keyed by the version the
/// subscriber held, the head it moves to, and the `Fresh` (by its `at`),
/// the last few kept. See the module docs.
#[derive(Debug, Default)]
pub(crate) struct FrameCache {
    /// `(have, head, fresh.at)` → the encoded frame, newest last.
    frames: Mutex<Vec<(FrameKey, Arc<Vec<u8>>)>>,
}

/// What a cached frame is for.
type FrameKey = (StateVersion, StateVersion, i64);

/// How many encoded frames a directory keeps for its subscribers.
const CACHED_FRAMES: usize = 8;

impl FrameCache {
    /// The encoded frame for a subscriber at `sent` (see [`next_frame`]),
    /// from the cache or made and cached now.
    fn frame(
        &self,
        dir: &Directory,
        c: &Current,
        fresh: &Fresh,
        sent: StateVersion,
    ) -> Result<Option<(Arc<Vec<u8>>, StateVersion)>> {
        let version = c.held.version();
        if sent > version {
            return Ok(None);
        }
        let key = (sent, version, fresh.at);
        let hit = self
            .frames
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .find(|(k, _)| *k == key)
            .map(|(_, bytes)| Arc::clone(bytes));
        if let Some(bytes) = hit {
            return Ok(Some((bytes, version)));
        }
        let Some((frame, to)) = next_frame(dir, c, fresh, sent) else {
            return Ok(None);
        };
        let bytes = Arc::new(frame.encode()?);
        let mut frames = self.frames.lock().unwrap_or_else(|e| e.into_inner());
        frames.retain(|(k, _)| *k != key);
        frames.push((key, Arc::clone(&bytes)));
        let over = frames.len().saturating_sub(CACHED_FRAMES);
        frames.drain(..over);
        Ok(Some((bytes, to)))
    }
}

/// Serve one host's `policy` subscription on `send` (the `hello` and the
/// `subscribe {kind: policy, have}` already read and admitted) until the
/// host goes away or this node stops being a directory. Takes one of the
/// directory's subscriber slots, or refuses when the cap is reached.
pub(crate) async fn serve(
    dir: &Directory,
    conn: &Connection,
    send: &mut SendStream,
    caller: NodeId,
    have: StateVersion,
) -> Result<()> {
    let Ok(_slot) = Arc::clone(&dir.subscribers).try_acquire_owned() else {
        return deny(
            send,
            format!(
                "this directory's subscriber cap ({}) is reached",
                dir.max_subscribers
            ),
        )
        .await;
    };
    tracing::info!(peer = %caller.hex(), have = have.0, "policy subscriber");
    let mut sent = have;
    let mut changes = dir.watch();
    loop {
        let snapshot = changes.borrow_and_update().clone();
        if let Some(c) = snapshot {
            let Some(fresh) = c.fresh.clone() else {
                // The head no longer lists this node: it vouches for nothing.
                return deny(send, "no longer a directory of this network".into()).await;
            };
            if let Some((bytes, to)) = dir.policy_frames.frame(dir, &c, &fresh, sent)? {
                wire::write(send, &bytes).await?;
                sent = to;
            }
        }
        tokio::select! {
            changed = changes.changed() => if changed.is_err() { return Ok(()); },
            _ = conn.closed() => return Ok(()),
        }
    }
}

/// End a subscription with `denied {reason}`.
async fn deny(send: &mut SendStream, reason: String) -> Result<()> {
    let frame = SubFrame::Denied {
        reason: crate::host::transport::truncate_reason(reason),
    };
    wire::write(send, &frame.encode()?).await?;
    send.finish().ok();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::admin::keystore::Keystore;
    use library::{DirectoryAnswer, DirectoryRequest, NodeIdentity, Policy, SignedPolicy};
    use proptest::prelude::*;

    fn root() -> NodeIdentity {
        NodeIdentity::from_seed([1u8; 32])
    }

    fn me() -> NodeIdentity {
        NodeIdentity::from_seed([40u8; 32])
    }

    /// Versions 1..=`n`, each banning one more node, each signed after the
    /// last.
    fn versions(n: u64) -> Vec<SignedPolicy> {
        let mut out: Vec<SignedPolicy> = Vec::new();
        for v in 1..=n {
            let mut p = Policy::new(root().node_id());
            p.version = StateVersion(v);
            p.not_after = i64::MAX;
            p.directories = vec![me().node_id()];
            for b in 0..v {
                p.ban(
                    NodeIdentity::from_seed([100 + b as u8; 32]).node_id(),
                    i64::MAX,
                );
            }
            let signed = match out.last() {
                Some(prev) => p.sign_after(&root(), prev).unwrap(),
                None => p.sign(&root()).unwrap(),
            };
            out.push(signed);
        }
        out
    }

    /// A directory that took every one of `policies`, in order.
    fn directory(policies: &[SignedPolicy]) -> Arc<Directory> {
        let ks = Arc::new(Keystore::at(crate::testutil::temp_dir()));
        let dir = Directory::open(me(), root().node_id(), ks, 4, 0).unwrap();
        for p in policies {
            assert!(dir.accept(p, 0).unwrap());
        }
        dir
    }

    fn ask(dir: &Directory, have: u64) -> DirectoryAnswer {
        let caller = NodeIdentity::from_seed([50u8; 32]).node_id();
        dir.answer(
            caller,
            DirectoryRequest::Policy {
                have: StateVersion(have),
            },
            0,
        )
    }

    #[test]
    fn a_policy_request_gets_a_delta_from_a_kept_head() {
        let all = versions(3);
        let dir = directory(&all);
        assert!(matches!(ask(&dir, 0), DirectoryAnswer::Policy { policy, .. } if policy == all[2]));
        let DirectoryAnswer::PolicyUpdate { update, fresh } = ask(&dir, 1) else {
            panic!("expected a policy_update");
        };
        assert_eq!(all[0].apply(&update, root().node_id()).unwrap(), all[2]);
        fresh.verify(&all[2].head).unwrap();
        assert!(matches!(ask(&dir, 3), DirectoryAnswer::Current { .. }));
        // Newer than the directory's own: nothing to send.
        assert!(matches!(ask(&dir, 9), DirectoryAnswer::Current { .. }));
    }

    #[test]
    fn a_head_no_longer_kept_gets_the_whole_policy() {
        let n = super::super::db::KEEP_HEADS as u64 + 2;
        let all = versions(n);
        let dir = directory(&all);
        assert!(matches!(ask(&dir, 1), DirectoryAnswer::Policy { .. }));
        assert!(matches!(
            ask(&dir, n - 1),
            DirectoryAnswer::PolicyUpdate { .. }
        ));
    }

    #[test]
    fn subscribers_at_one_version_share_one_encoded_frame() {
        let all = versions(3);
        let dir = directory(&all);
        let c = dir.snapshot().unwrap();
        let fresh = c.fresh.clone().unwrap();
        let frame = |have: u64| {
            dir.policy_frames
                .frame(&dir, &c, &fresh, StateVersion(have))
                .unwrap()
        };
        let (a, to) = frame(1).unwrap();
        let (b, _) = frame(1).unwrap();
        assert!(Arc::ptr_eq(&a, &b));
        assert_eq!(to, StateVersion(3));
        let Some((SubFrame::PolicyUpdate { update, .. }, _)) = SubFrame::decode(&a).unwrap() else {
            panic!("expected a policy_update");
        };
        assert_eq!(all[0].apply(&update, root().node_id()).unwrap(), all[2]);
        // At the head: a beat. Ahead of it: nothing.
        let (beat, _) = frame(3).unwrap();
        assert!(matches!(
            SubFrame::decode(&beat).unwrap(),
            Some((SubFrame::Fresh { .. }, _))
        ));
        assert!(frame(4).is_none());
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(16))]

        /// From any version a subscriber may hold, what the directory sends
        /// brings it to the newest head exactly.
        #[test]
        fn what_since_sends_always_reaches_the_newest(n in 1u64..6, have in 0u64..8) {
            let all = versions(n);
            let dir = directory(&all);
            let c = dir.snapshot().unwrap();
            let newest = &all[all.len() - 1];
            match since(&dir, &c, StateVersion(have)) {
                Since::Current => prop_assert!(have >= n),
                Since::Whole => prop_assert_eq!(have, 0),
                Since::Update(update) => {
                    let held = &all[have as usize - 1];
                    prop_assert_eq!(&held.apply(&update, root().node_id()).unwrap(), newest);
                }
            }
        }
    }
}
