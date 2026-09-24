//! The host's freshness (card 36c): the newest [`Fresh`] a directory signed
//! for the head this host decides under, and the rule for when it lapses.
//!
//! A directory signs `Fresh {version, head, at, until}` for its newest head
//! every `settings.beat_secs`; it is valid because the root-signed head
//! lists the signer in `directories`. The host keeps the newest one that
//! vouches for its own head, in memory and in `fresh.json` (so a restarted
//! host still knows, before any directory answers, how recently its copy
//! was vouched for). Every frame of the host's `policy` subscription
//! ([`follow`](super::follow)) carries one, and a host that is itself a
//! directory takes its own.
//!
//! When no current `Fresh` names the held head ([`Vouched::Lapsed`]: every
//! directory is down, or none has vouched for this head yet), the signed
//! `settings.freshness` decides ([`ServicesHost::decide`](super::gate::ServicesHost::decide)):
//!
//! - `lenient` (the default): keep deciding under the held head until its
//!   `not_after`, and say so in the host's trace (throttled). Calls never
//!   depend on a directory.
//! - `strict`: refuse every call with [`STALE`] until a current `Fresh`
//!   arrives. Bans then take effect within `settings.fresh_secs` on every
//!   host, at the cost of the directories becoming a dependency for calls.
//!
//! ```text
//! wires state settings --freshness strict   # admin: the rule, signed into the policy
//! ```

use std::sync::{Arc, RwLock};

use anyhow::{Context, Result};
#[cfg(test)]
use library::StateVersion;
use library::{Fresh, SignedPolicyHead};

use crate::admin::keystore::{Keystore, write_text_mode};

/// The file under `$WIRES_HOME` holding the newest `Fresh` for the held
/// head.
pub(crate) const FRESH_FILE: &str = "fresh.json";

/// What a strict host says when it refuses a call because its policy is
/// not vouched for.
pub(crate) const STALE: &str = "this host's policy is stale: no directory has vouched for it \
                                recently; try again later";

/// Whether the head a host decides under is vouched for now.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Vouched {
    /// A current `Fresh` from a directory the head lists names this exact
    /// head.
    Current,
    /// None does.
    Lapsed {
        /// When the newest `Fresh` for this head ran out (`until`); `None`
        /// when this host holds none for it.
        since: Option<i64>,
    },
}

/// The host's freshness: the newest verified `Fresh`, in memory and in
/// [`FRESH_FILE`]. See the module docs.
pub(crate) struct Freshness {
    /// Where [`FRESH_FILE`] lives.
    ks: Arc<Keystore>,
    /// The newest `Fresh` offered that verified against the head it was
    /// offered for.
    held: RwLock<Option<Fresh>>,
}

impl std::fmt::Debug for Freshness {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Freshness")
            .field("held", &self.held)
            .finish_non_exhaustive()
    }
}

impl Freshness {
    /// The host's freshness from `ks`: its [`FRESH_FILE`], kept only if it
    /// vouches for `head` (the head on disk; `None`: no policy yet, so
    /// nothing is kept). A missing or unreadable file is no `Fresh`, never
    /// an error: freshness only ever arrives from a directory again.
    pub(crate) fn load(ks: Arc<Keystore>, head: Option<&SignedPolicyHead>) -> Freshness {
        let held = std::fs::read_to_string(ks.path(FRESH_FILE))
            .ok()
            .and_then(|text| serde_json::from_str::<Fresh>(text.trim()).ok())
            .filter(|f| head.is_some_and(|h| f.verify(h).is_ok()));
        Freshness {
            ks,
            held: RwLock::new(held),
        }
    }

    /// Keep `fresh` if it vouches for `head` (the head this host holds now,
    /// already verified under the root: see [`Fresh::verify`]) and is newer
    /// than the one held: for a newer head, or the same head with a later
    /// `until`. Writes [`FRESH_FILE`] when it keeps it. `Ok(false)`: not
    /// newer. `Err`: it doesn't vouch for `head` (another head, a signer the
    /// head doesn't list, a bad signature), and nothing changes.
    pub(crate) fn offer(&self, fresh: &Fresh, head: &SignedPolicyHead) -> Result<bool> {
        fresh
            .verify(head)
            .context("the freshness doesn't vouch for the held head")?;
        {
            let mut held = self.held.write().unwrap_or_else(|e| e.into_inner());
            let newer = held
                .as_ref()
                .is_none_or(|h| (fresh.version, fresh.until) > (h.version, h.until));
            if !newer {
                return Ok(false);
            }
            *held = Some(fresh.clone());
        }
        let text = serde_json::to_string(fresh).context("encoding a freshness")?;
        write_text_mode(&self.ks.path(FRESH_FILE), &format!("{text}\n"), Some(0o600))?;
        Ok(true)
    }

    /// Whether `head` is vouched for at `now`: the held `Fresh` names this
    /// exact head (version and hash) and is current.
    pub(crate) fn vouched(&self, head: &SignedPolicyHead, now: i64) -> Vouched {
        let held = self.held.read().unwrap_or_else(|e| e.into_inner());
        let for_head = held
            .as_ref()
            .filter(|f| f.version == head.head.version && head.hash().is_ok_and(|h| h == f.head));
        match for_head {
            Some(f) if f.is_current(now) => Vouched::Current,
            Some(f) => Vouched::Lapsed {
                since: Some(f.until),
            },
            None => Vouched::Lapsed { since: None },
        }
    }

    /// The version the held `Fresh` vouches for (0: none).
    #[cfg(test)]
    pub(crate) fn version(&self) -> StateVersion {
        self.held
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
            .map_or(StateVersion(0), |f| f.version)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use library::{NodeIdentity, Policy};

    /// Root 1, directory 30: the head at `version`, listing the directory.
    fn head(version: u64) -> SignedPolicyHead {
        let root = NodeIdentity::from_seed([1u8; 32]);
        let mut p = Policy::new(root.node_id());
        p.version = StateVersion(version);
        p.not_after = i64::MAX;
        p.directories = vec![dir().node_id()];
        crate::testutil::signed_policy(&root, p).head
    }

    fn dir() -> NodeIdentity {
        NodeIdentity::from_seed([30u8; 32])
    }

    fn fresh(head: &SignedPolicyHead, at: i64, until: i64) -> Fresh {
        Fresh::sign(&dir(), head, at, until).unwrap()
    }

    fn freshness() -> Freshness {
        Freshness::load(Arc::new(Keystore::at(crate::testutil::temp_dir())), None)
    }

    #[test]
    fn a_current_fresh_for_the_held_head_vouches_until_it_lapses() {
        let f = freshness();
        let h = head(2);
        assert_eq!(f.vouched(&h, 100), Vouched::Lapsed { since: None });
        assert!(f.offer(&fresh(&h, 100, 200), &h).unwrap());
        assert_eq!(f.vouched(&h, 150), Vouched::Current);
        assert_eq!(f.vouched(&h, 200), Vouched::Current);
        assert_eq!(f.vouched(&h, 201), Vouched::Lapsed { since: Some(200) });
        // It vouches for that head only.
        assert_eq!(f.vouched(&head(3), 150), Vouched::Lapsed { since: None });
    }

    #[test]
    fn only_newer_freshness_is_kept() {
        let f = freshness();
        let h = head(2);
        assert!(f.offer(&fresh(&h, 100, 200), &h).unwrap());
        assert!(!f.offer(&fresh(&h, 50, 150), &h).unwrap());
        assert!(!f.offer(&fresh(&h, 100, 200), &h).unwrap());
        assert!(f.offer(&fresh(&h, 150, 300), &h).unwrap());
        // A newer head's, however short.
        let h3 = head(3);
        assert!(f.offer(&fresh(&h3, 10, 20), &h3).unwrap());
        assert_eq!(f.version(), StateVersion(3));
    }

    #[test]
    fn a_fresh_for_another_head_or_from_an_unlisted_node_is_refused() {
        let f = freshness();
        let (h2, h3) = (head(2), head(3));
        assert!(f.offer(&fresh(&h3, 100, 200), &h2).is_err());
        // Signed by a node the head doesn't list: its signature is fine, but
        // it vouches for nothing.
        let mut stranger = fresh(&h2, 100, 200);
        stranger.directory = NodeIdentity::from_seed([31u8; 32]).node_id();
        assert!(f.offer(&stranger, &h2).is_err());
        assert_eq!(f.version(), StateVersion(0));
    }

    #[test]
    fn a_restarted_host_reads_its_freshness_back_for_the_same_head_only() {
        let home = crate::testutil::temp_dir();
        let ks = Arc::new(Keystore::at(&home));
        let h = head(2);
        Freshness::load(Arc::clone(&ks), Some(&h))
            .offer(&fresh(&h, 100, 200), &h)
            .unwrap();
        let back = Freshness::load(Arc::clone(&ks), Some(&h));
        assert_eq!(back.vouched(&h, 150), Vouched::Current);
        // Under another head (or none) the file vouches for nothing.
        let other = Freshness::load(Arc::clone(&ks), Some(&head(3)));
        assert_eq!(other.version(), StateVersion(0));
        assert_eq!(Freshness::load(ks, None).version(), StateVersion(0));
    }

    #[test]
    fn a_garbled_file_is_no_freshness() {
        let home = crate::testutil::temp_dir();
        std::fs::create_dir_all(&home).unwrap();
        std::fs::write(home.join(FRESH_FILE), "{not json").unwrap();
        let f = Freshness::load(Arc::new(Keystore::at(&home)), Some(&head(2)));
        assert_eq!(f.version(), StateVersion(0));
    }
}
