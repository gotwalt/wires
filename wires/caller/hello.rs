//! The caller's half of the session handshake: build the [`Hello`] from what
//! this node holds: its membership, the version of its signed state, and its
//! stored ID token from `wires login` (the token travels in the handshake).

use anyhow::{Context, Result};
use library::{Hello, IdToken, Membership, StateVersion};

use crate::admin::keystore::Keystore;
use crate::caller::login::ID_TOKEN_FILE;
use crate::state::store;

/// Build this node's [`Hello`]. A missing ID token is not an error (the host
/// decides whether the service needs one); a missing membership is.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn build(ks: &Keystore) -> Result<Hello> {
    let membership = ks
        .read_membership()?
        .context("this node has no membership: run `wires join <token>` first")?;
    with_membership(ks, membership)
}

/// [`build`] with a membership resolved elsewhere (a `--membership` flag):
/// the state version and ID token still come from `ks`. A stored state that
/// fails to verify counts as none (version 0): the host then hands back its
/// own.
pub(crate) fn with_membership(ks: &Keystore, membership: Membership) -> Result<Hello> {
    let state_version = match store::read(ks, membership.fabric) {
        Ok(Some(s)) => s.state.version,
        Ok(None) => StateVersion(0),
        Err(e) => {
            tracing::warn!("the stored signed state is unusable: {e:#}");
            StateVersion(0)
        }
    };
    Ok(Hello {
        membership,
        state_version,
        id_token: stored_token(ks),
    })
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
    use library::{NodeIdentity, State};

    fn keystore() -> Keystore {
        Keystore::at(crate::testutil::temp_dir())
    }

    #[test]
    fn no_membership_is_an_error() {
        let err = build(&keystore()).unwrap_err().to_string();
        assert!(err.contains("wires join"), "{err}");
    }

    #[test]
    fn carries_membership_state_version_and_token() {
        let root = NodeIdentity::from_seed([1; 32]);
        let me = NodeIdentity::from_seed([2; 32]);
        let ks = keystore();
        let m = Membership::mint(&root, me.node_id(), 0, i64::MAX).unwrap();
        ks.save_membership(&m).unwrap();

        let h = build(&ks).unwrap();
        assert_eq!(h.membership, m);
        assert_eq!(h.state_version, StateVersion(0));
        assert_eq!(h.id_token, None);

        let mut s = State::new(root.node_id());
        s.version = StateVersion(4);
        s.issued = 1;
        s.not_after = i64::MAX;
        let signed = s.sign(&root).unwrap();
        store::adopt_if_newer(&ks, &signed, root.node_id(), 10).unwrap();
        std::fs::write(ks.path(ID_TOKEN_FILE), "a.b.c\n").unwrap();

        let h = build(&ks).unwrap();
        assert_eq!(h.state_version, StateVersion(4));
        assert_eq!(h.id_token, Some(IdToken::new("a.b.c")));
    }
}
