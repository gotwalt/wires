//! `wires state settings`: the fabric-wide settings in the signed policy
//! (card 36c): the freshness rule, and how often directories vouch.
//!
//! - `--freshness lenient | strict`: what a host does when no directory has
//!   vouched for its policy recently ([`crate::host::freshness`]).
//! - `--beat-secs N`: how often each directory signs a new `Fresh` (and
//!   beats its subscriptions).
//! - `--fresh-secs N`: how long each `Fresh` is good for (at least the
//!   beat).
//!
//! With no flag it prints the settings and edits nothing; with any, it signs
//! the next policy and publishes it, like every admin edit.
//!
//! ```text
//! wires state settings                        # print them
//! wires state settings --freshness strict     # bans honoured within 15 min, or no calls
//! ```

use anyhow::{Result, anyhow};
use clap::{Args, ValueEnum};
use library::{FreshnessMode, Settings};

use super::keystore::Keystore;
use super::service::edit_policy;
use super::ttl::Ttl;
use crate::policy::store;

/// `state settings` arguments. None given: print the settings.
#[derive(Args, Debug, Default)]
pub(crate) struct SettingsArgs {
    /// When no directory has vouched for a host's policy lately: keep deciding, or refuse
    // `lenient` keeps deciding (and traces it), `strict` refuses every call
    // until a directory vouches again.
    #[arg(long, value_enum)]
    pub(crate) freshness: Option<Freshness>,
    /// How often each directory signs a new freshness timestamp, in
    /// seconds.
    #[arg(long)]
    pub(crate) beat_secs: Option<u32>,
    /// How long each freshness timestamp is good for, in seconds (at least the beat).
    #[arg(long)]
    pub(crate) fresh_secs: Option<u32>,
    /// Lifetime of the new policy, from now; never shortens the current one.
    #[arg(long = "state-ttl", default_value = Ttl::POLICY_DEFAULT, hide = true)]
    pub(crate) ttl: Ttl,
}

/// `--freshness` values.
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub(crate) enum Freshness {
    /// Keep deciding under the held policy until it expires.
    Lenient,
    /// Refuse calls until a directory vouches again.
    Strict,
}

impl From<Freshness> for FreshnessMode {
    fn from(f: Freshness) -> FreshnessMode {
        match f {
            Freshness::Lenient => FreshnessMode::Lenient,
            Freshness::Strict => FreshnessMode::Strict,
        }
    }
}

impl SettingsArgs {
    /// Whether any setting is given (an edit), rather than none (print).
    pub(crate) fn is_edit(&self) -> bool {
        self.freshness.is_some() || self.beat_secs.is_some() || self.fresh_secs.is_some()
    }

    /// `settings` with the given ones changed.
    fn apply(&self, settings: &mut Settings) {
        if let Some(f) = self.freshness {
            settings.freshness = f.into();
        }
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
    let mode = match settings.freshness {
        FreshnessMode::Lenient => "lenient",
        FreshnessMode::Strict => "strict",
    };
    format!(
        "freshness {mode}; beat {} s; fresh {} s",
        settings.beat_secs, settings.fresh_secs
    )
}

/// Run `state settings` against `ks` (no publish): print the settings, or
/// sign the next policy with them changed (refused when invalid: a zero
/// beat, or freshness shorter than the beat).
pub(crate) fn settings_in(ks: &Keystore, a: &SettingsArgs) -> Result<String> {
    if !a.is_edit() {
        let root = store::fabric(ks)?.ok_or_else(|| anyhow!("this keystore is in no network"))?;
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
        let before = store::read(&ks, store::fabric(&ks).unwrap().unwrap())
            .unwrap()
            .unwrap()
            .version();
        let out = settings_in(&ks, &SettingsArgs::default()).unwrap();
        assert!(
            out.starts_with("freshness lenient; beat 300 s; fresh 900 s"),
            "{out}"
        );
        let after = store::read(&ks, store::fabric(&ks).unwrap().unwrap())
            .unwrap()
            .unwrap()
            .version();
        assert_eq!(before, after);
    }

    #[test]
    fn an_edit_signs_the_next_policy() {
        let ks = admin();
        let a = SettingsArgs {
            freshness: Some(Freshness::Strict),
            beat_secs: Some(60),
            fresh_secs: Some(180),
            ..SettingsArgs::default()
        };
        let out = settings_in(&ks, &a).unwrap();
        assert!(
            out.contains("freshness strict; beat 60 s; fresh 180 s"),
            "{out}"
        );
        let held = store::read(&ks, store::fabric(&ks).unwrap().unwrap())
            .unwrap()
            .unwrap();
        assert_eq!(held.policy.settings.freshness, FreshnessMode::Strict);
        assert_eq!(held.policy.settings.beat_secs, 60);
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
