//! `wires policy settings`: the network-wide settings in the signed policy
//! (cards 36c and 49): how often directories vouch, and for how long.
//!
//! - `--beat-secs N`: how often each directory signs a new `Fresh` (and
//!   beats its subscriptions).
//! - `--fresh-secs N`: how long each `Fresh` is good for (at least the
//!   beat). It is the removed-host window: a caller sends a host nothing
//!   until a current `Fresh` from another directory vouches for the host's
//!   policy ([`crate::caller::vouch`]), so a host the admin removed can
//!   still be called for at most this long after the edit reaches the
//!   directories; and with every directory down, calls stop after it.
//!
//! With no flag it prints the settings and edits nothing; with any, it signs
//! the next policy and publishes it, like every admin edit.
//!
//! ```text
//! wires policy settings                    # print them
//! wires policy settings --fresh-secs 300   # removal holds within 5 min
//! ```

use anyhow::{Result, anyhow};
use clap::Args;
use library::Settings;

use super::keystore::Keystore;
use super::service::edit_policy;
use super::ttl::Ttl;
use crate::policy::store;

/// `policy settings` arguments. None given: print the settings.
#[derive(Args, Debug, Default)]
pub(crate) struct SettingsArgs {
    /// How often each directory signs a new freshness timestamp, in
    /// seconds.
    #[arg(long)]
    pub(crate) beat_secs: Option<u32>,
    /// How long each freshness timestamp is good for, in seconds (at least the beat)
    // The removed-host window: a caller sends a host nothing without a
    // current one from another directory.
    #[arg(long)]
    pub(crate) fresh_secs: Option<u32>,
    /// Lifetime of the new policy, from now; never shortens the current one.
    #[arg(long = "policy-ttl", default_value = Ttl::POLICY_DEFAULT, hide = true)]
    pub(crate) ttl: Ttl,
}

impl SettingsArgs {
    /// Whether any setting is given (an edit), rather than none (print).
    pub(crate) fn is_edit(&self) -> bool {
        self.beat_secs.is_some() || self.fresh_secs.is_some()
    }

    /// `settings` with the given ones changed.
    fn apply(&self, settings: &mut Settings) {
        if let Some(b) = self.beat_secs {
            settings.beat_secs = b;
        }
        if let Some(f) = self.fresh_secs {
            settings.fresh_secs = f;
        }
    }
}

/// One line for `settings`.
pub(crate) fn line(settings: &Settings) -> String {
    format!(
        "beat {} s; fresh {} s",
        settings.beat_secs, settings.fresh_secs
    )
}

/// Run `policy settings` against `ks` (no publish): print the settings, or
/// sign the next policy with them changed (refused when invalid: a zero
/// beat, or freshness shorter than the beat).
pub(crate) fn settings_in(ks: &Keystore, a: &SettingsArgs) -> Result<String> {
    if !a.is_edit() {
        let root = ks
            .network_root()?
            .ok_or_else(|| anyhow!("this keystore is in no network"))?;
        let held = store::require_policy(ks, root)?;
        return Ok(format!(
            "{} (policy version {})",
            line(&held.policy.settings),
            held.version().0
        ));
    }
    let held = edit_policy(ks, a.ttl, |p| {
        a.apply(&mut p.settings);
        Ok(())
    })?;
    Ok(format!(
        "settings: {} (policy version {})",
        line(&held.policy.settings),
        held.version().0
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::admin::init::{InitArgs, init_in};
    use crate::testutil::temp_dir;

    fn admin() -> Keystore {
        let ks = Keystore::at(temp_dir());
        init_in(&ks, InitArgs::default()).unwrap();
        ks
    }

    #[test]
    fn no_flag_prints_and_edits_nothing() {
        let ks = admin();
        let before = store::read(&ks, ks.network_root().unwrap().unwrap())
            .unwrap()
            .unwrap()
            .version();
        let out = settings_in(&ks, &SettingsArgs::default()).unwrap();
        assert!(out.starts_with("beat 300 s; fresh 900 s"), "{out}");
        let after = store::read(&ks, ks.network_root().unwrap().unwrap())
            .unwrap()
            .unwrap()
            .version();
        assert_eq!(before, after);
    }

    #[test]
    fn an_edit_signs_the_next_policy() {
        let ks = admin();
        let a = SettingsArgs {
            beat_secs: Some(60),
            fresh_secs: Some(180),
            ..SettingsArgs::default()
        };
        let out = settings_in(&ks, &a).unwrap();
        assert!(out.contains("beat 60 s; fresh 180 s"), "{out}");
        let held = store::read(&ks, ks.network_root().unwrap().unwrap())
            .unwrap()
            .unwrap();
        assert_eq!(held.policy.settings.beat_secs, 60);
        assert_eq!(held.policy.settings.fresh_secs, 180);
    }

    #[test]
    fn invalid_settings_are_refused() {
        let ks = admin();
        for a in [
            SettingsArgs {
                beat_secs: Some(0),
                ..SettingsArgs::default()
            },
            SettingsArgs {
                fresh_secs: Some(10),
                ..SettingsArgs::default()
            },
        ] {
            assert!(settings_in(&ks, &a).is_err(), "{a:?}");
        }
    }
}
