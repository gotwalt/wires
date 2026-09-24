//! The caller's half of the session handshake: build the [`Hello`] from what
//! this node holds: its membership, the head version of its view, and its
//! stored ID token from `wires login` (the token travels in the handshake).

use library::{Hello, IdToken, Membership, StateVersion};

use crate::admin::keystore::Keystore;
use crate::caller::login::ID_TOKEN_FILE;
use crate::caller::view;

/// Build this node's [`Hello`] around `membership` (from the keystore or a
/// `--membership` flag); the view's head version and the ID token come from
/// `ks`. A missing ID token is not an error (the host decides whether the
/// service needs one). A stored view that fails to verify counts as none
/// (version 0): the host then hands back its head.
pub(crate) fn with_membership(ks: &Keystore, membership: Membership) -> Hello {
    let state_version = match view::read(ks, membership.fabric) {
        Ok(Some(held)) => held.version(),
        Ok(None) => StateVersion(0),
        Err(e) => {
            tracing::warn!("the stored view is unusable: {e:#}");
            StateVersion(0)
        }
    };
    Hello {
        membership,
        state_version,
        id_token: stored_token(ks),
    }
}

/// The ID token `wires login` stored, if any.
pub(crate) fn stored_token(ks: &Keystore) -> Option<IdToken> {
    let text = std::fs::read_to_string(ks.path(ID_TOKEN_FILE)).ok()?;
    let text = text.trim();
    (!text.is_empty()).then(|| IdToken::new(text))
}

#[cfg(test)]
mod tests {
    use super::*;
    use library::{NodeIdentity, Policy};

    fn keystore() -> Keystore {
        Keystore::at(crate::testutil::temp_dir())
    }

    #[test]
    fn carries_membership_view_version_and_token() {
        let root = NodeIdentity::from_seed([1; 32]);
        let me = NodeIdentity::from_seed([2; 32]);
        let ks = keystore();
        let m = Membership::mint(&root, me.node_id(), 0, i64::MAX).unwrap();
        ks.save_membership(&m).unwrap();

        let h = with_membership(&ks, m.clone());
        assert_eq!(h.membership, m);
        assert_eq!(h.state_version, StateVersion(0));
        assert_eq!(h.id_token, None);

        let mut s = Policy::new(root.node_id());
        s.version = StateVersion(4);
        s.issued = 1;
        s.not_after = i64::MAX;
        let signed = crate::testutil::signed_policy(&root, s);
        let held = view::HeldView::fetched(signed.view_for(None, None), None, 10);
        view::write(&ks, root.node_id(), &held).unwrap();
        std::fs::write(ks.path(ID_TOKEN_FILE), "a.b.c\n").unwrap();

        let h = with_membership(&ks, m.clone());
        assert_eq!(h.state_version, StateVersion(4));
        assert_eq!(h.id_token, Some(IdToken::new("a.b.c")));
    }
}
