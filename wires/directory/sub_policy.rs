//! A host's subscription to the policy (`wires/directory-sub/3`), the
//! directory side.
//!
//! A host (or another directory that is also a host) subscribes with the
//! version it holds (`have`; 0: none). The directory sends, on one
//! long-lived stream, at once and on every change of what it holds (a new
//! head, or a beat every `settings.beat_secs`):
//!
//! - the whole `policy {policy, fresh}` when its head is newer than what
//!   the subscriber has (its `have`, then the last policy sent it): there
//!   are no deltas (card 45);
//! - else `fresh {fresh}`, its `Fresh` for its own head, even when the
//!   subscriber holds a newer head: so the subscriber learns this directory
//!   is behind it, and follows another.
//!
//! The stream ends with `denied` when this node stops being a directory
//! (it can no longer vouch), and the host fails over to another. Every
//! head is checked as the subscription's opening was: one that bans the
//! subscriber, or no longer names it as a host or a directory, ends the
//! stream with `denied` too.
//!
//! Every subscriber gets the same bytes: each frame is encoded once per
//! head and `Fresh` ([`Current::frame`]), not once per subscriber.

use std::sync::Arc;

use anyhow::Result;
use iroh::endpoint::{Connection, SendStream};
use library::{NodeId, StateVersion, SubFrame};

use super::node::{Current, Directory, NOT_ADMITTED, VIEW_NOT_POLICY};
use super::wire;

/// The frame a subscriber that has `sent` gets for `c`: the whole policy
/// when `c`'s head is newer, else the beat; and the version it then has.
/// `None` when `c` holds no `Fresh`.
pub(crate) fn next_frame(
    c: &Current,
    sent: StateVersion,
) -> Result<Option<(Arc<Vec<u8>>, StateVersion)>> {
    let version = c.held.version();
    let whole = version > sent;
    Ok(c.frame(whole)?
        .map(|bytes| (bytes, if whole { version } else { sent })))
}

/// Serve one host's subscription on `send` (the `hello` and the
/// `subscribe {have}` already read, the subscriber named by the held
/// policy) until it goes away, this node stops being a directory, or a new
/// head bans the subscriber or no longer names it as a host or directory:
/// each ends the stream with `denied`. Takes one of the directory's
/// subscriber slots, or refuses when the cap is reached.
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
            if c.fresh.is_none() {
                // The head no longer lists this node: it vouches for nothing.
                return deny(send, "no longer a directory of this network".into()).await;
            }
            if c.held.policy.bans_node(caller) {
                tracing::info!(peer = %caller.hex(), "policy subscription ended: removed");
                return deny(send, NOT_ADMITTED.into()).await;
            }
            if !dir.holds_whole(caller) {
                return deny(send, VIEW_NOT_POLICY.into()).await;
            }
            if let Some((bytes, to)) = next_frame(&c, sent)? {
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
                p.ban(NodeIdentity::from_seed([100 + b as u8; 32]).node_id());
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
        // A directory the policy lists (card 37: only hosts and
        // directories get the whole policy).
        let peer = super::super::node::Peer {
            node: me().node_id(),
            named: true,
            principal: None,
        };
        dir.answer(
            &peer,
            DirectoryRequest::Policy {
                have: StateVersion(have),
            },
            0,
        )
    }

    #[test]
    fn a_policy_request_gets_the_whole_policy_unless_current() {
        let all = versions(3);
        let dir = directory(&all);
        for have in [0, 1, 2] {
            let DirectoryAnswer::Policy { policy, fresh } = ask(&dir, have) else {
                panic!("expected the whole policy from {have}");
            };
            assert_eq!(policy, all[2]);
            fresh.verify(&all[2].head).unwrap();
        }
        assert!(matches!(ask(&dir, 3), DirectoryAnswer::Current { .. }));
        // Newer than the directory's own: nothing to send but its word.
        assert!(matches!(ask(&dir, 9), DirectoryAnswer::Current { .. }));
    }

    #[test]
    fn subscribers_share_one_encoded_frame() {
        let all = versions(3);
        let dir = directory(&all);
        let c = dir.snapshot().unwrap();
        let (a, to) = next_frame(&c, StateVersion(1)).unwrap().unwrap();
        let (b, _) = next_frame(&c, StateVersion(0)).unwrap().unwrap();
        assert!(Arc::ptr_eq(&a, &b));
        assert_eq!(to, StateVersion(3));
        let Some((SubFrame::Policy { policy, .. }, _)) = SubFrame::decode(&a).unwrap() else {
            panic!("expected the whole policy");
        };
        assert_eq!(policy, all[2]);
        // At the head, and ahead of it: the beat, and the version stays.
        for have in [3, 4] {
            let (beat, to) = next_frame(&c, StateVersion(have)).unwrap().unwrap();
            assert_eq!(to, StateVersion(have));
            assert!(matches!(
                SubFrame::decode(&beat).unwrap(),
                Some((SubFrame::Fresh { .. }, _))
            ));
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(16))]

        /// From any version a subscriber may hold, the first frame brings it
        /// to the newest head exactly, or says the directory's own head.
        #[test]
        fn the_first_frame_always_reaches_the_newest(n in 1u64..6, have in 0u64..8) {
            let all = versions(n);
            let dir = directory(&all);
            let c = dir.snapshot().unwrap();
            let newest = &all[all.len() - 1];
            let (bytes, to) = next_frame(&c, StateVersion(have)).unwrap().unwrap();
            match SubFrame::decode(&bytes).unwrap().unwrap().0 {
                SubFrame::Policy { policy, .. } => {
                    prop_assert!(have < n);
                    prop_assert_eq!(&policy, newest);
                    prop_assert_eq!(to, StateVersion(n));
                }
                SubFrame::Fresh { fresh } => {
                    prop_assert!(have >= n);
                    prop_assert_eq!(fresh.version, StateVersion(n));
                }
                SubFrame::Denied { .. } => prop_assert!(false, "denied"),
            }
        }
    }
}
