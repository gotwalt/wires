//! Policy items: the leaves of the root-signed policy (card 36).
//!
//! The policy is a [head](crate::PolicyHead) over a sorted list of
//! [`Item`]s, one per role, service, ban, trusted issuer, and one for the
//! fabric's settings. Each item is addressed by its [`ItemKey`] (kind, then
//! key), which is also the order the leaves sit in the Merkle tree
//! ([`crate::merkle`]), so any subset can be handed out with inclusion proofs
//! and checked against the head alone.
//!
//! Items are signed only through the head's `items_root`: their bytes are the
//! canonical JSON of [`Item`], hashed into an [`ItemHash`](crate::ItemHash).
//! Like every signed body they have no optional fields and refuse unknown
//! ones.
//!
//! ```
//! use library::{Ban, Item, ItemKey, NodeIdentity};
//! let node = NodeIdentity::from_seed([2u8; 32]).node_id();
//! let ban = Item::Ban { key: node, body: Ban { until: 1_000 } };
//! assert_eq!(ban.key(), ItemKey::Ban(node));
//! assert!(ItemKey::Ban(node) < ItemKey::Settings, "sorted by kind, then key");
//! ```

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::identity::NodeId;
use crate::idp::{Audience, Issuer};
use crate::registry::{Service, ServiceName};
use crate::role::{Matcher, RoleName};

/// Default [`Settings::beat_secs`]: a directory signs a new
/// [`Fresh`](crate::Fresh) every 5 minutes.
pub const DEFAULT_BEAT_SECS: u32 = 5 * 60;

/// Default [`Settings::fresh_secs`]: each [`Fresh`](crate::Fresh) is good for
/// 15 minutes (three missed beats).
pub const DEFAULT_FRESH_SECS: u32 = 15 * 60;

/// Where an item sits in the policy: its kind, then its key. The derived
/// order (kinds in declaration order, then the key's own order) is the leaf
/// order of the Merkle tree, and a key names at most one item.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", content = "key", rename_all = "snake_case")]
pub enum ItemKey {
    /// A role, by name.
    Role(RoleName),
    /// A service, by name.
    Service(ServiceName),
    /// A ban, by the banned node.
    Ban(NodeId),
    /// A trusted IdP, by its issuer identifier.
    Issuer(Issuer),
    /// The fabric's one settings item.
    Settings,
}

impl fmt::Display for ItemKey {
    /// `kind:key` (`settings` alone), for messages and traces.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        todo!("ItemKey::fmt {f:p}")
    }
}

/// A ban: node `key` is refused everywhere until `until` (inclusive, unix
/// seconds), the not-after of the badge it cancels (card 35), so a ban never
/// outlives what it cancels.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Ban {
    /// The ban holds while `now <= until`.
    pub until: i64,
}

impl Ban {
    /// Whether the ban still holds at `now` (`now <= until`).
    pub fn holds(&self, now: i64) -> bool {
        todo!("Ban::holds {now}")
    }
}

/// A trusted IdP (the body of an `issuer` item; the issuer identifier is its
/// key). Moves what `host.json`'s `identity.issuers` says into signed policy;
/// a host can still narrow it locally.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IssuerConfig {
    /// The OAuth client id `wires login` asks this IdP for a token under.
    /// Empty: callers bring their own (no signed optionals).
    pub client_id: Audience,
    /// The `aud` values a host or directory accepts from this issuer. At
    /// least one.
    pub audiences: Vec<Audience>,
}

/// What a host does when its [`Fresh`](crate::Fresh) lapses (no directory
/// reachable).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FreshnessMode {
    /// Keep deciding under the held head until its `not_after`, and report
    /// the staleness. Calls never depend on a directory. The default.
    #[default]
    Lenient,
    /// Refuse calls until a current `Fresh` arrives: bans are honoured within
    /// [`Settings::fresh_secs`] everywhere, and a directory becomes a
    /// dependency for calls.
    Strict,
}

/// The fabric-wide settings (the body of the one `settings` item).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Settings {
    /// What a host does when its freshness lapses.
    pub freshness: FreshnessMode,
    /// How often each directory signs a new [`Fresh`](crate::Fresh), in
    /// seconds (also the subscription beat). More than zero.
    pub beat_secs: u32,
    /// How long each `Fresh` is good for, in seconds (`until - at`). At least
    /// `beat_secs`.
    pub fresh_secs: u32,
}

impl Default for Settings {
    /// `lenient`, a 5-minute beat, 15-minute freshness.
    fn default() -> Self {
        todo!("Settings::default")
    }
}

/// One leaf of the policy: a kind, a key and a body. Serialized (and hashed)
/// as `{"kind": …, "key": …, "body": …}`; the settings item has no key.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Item {
    /// A role definition: an OR of matchers over a verified principal.
    Role {
        /// The role's name.
        key: RoleName,
        /// Its matchers (at least one, each naming a trusted issuer).
        body: Vec<Matcher>,
    },
    /// A service registry entry.
    Service {
        /// The service's name.
        key: ServiceName,
        /// Who may call and read it, and which hosts run it.
        body: Service,
    },
    /// A removed node.
    Ban {
        /// The banned node.
        key: NodeId,
        /// Until when.
        body: Ban,
    },
    /// A trusted IdP.
    Issuer {
        /// The exact `iss` string.
        key: Issuer,
        /// Its client id and accepted audiences.
        body: IssuerConfig,
    },
    /// The fabric's settings (exactly one per policy).
    Settings {
        /// The settings.
        body: Settings,
    },
}

impl Item {
    /// This item's [`ItemKey`]: its kind and key, its place in the tree.
    pub fn key(&self) -> ItemKey {
        todo!("Item::key")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::canonical_bytes;
    use crate::identity::NodeIdentity;
    use proptest::prelude::*;

    fn node(b: u8) -> NodeId {
        NodeIdentity::from_seed([b; 32]).node_id()
    }

    fn json(item: &Item) -> String {
        String::from_utf8(canonical_bytes(item).unwrap()).unwrap()
    }

    #[test]
    fn keys_sort_by_kind_then_key() {
        let keys = [
            ItemKey::Role(RoleName::new("a").unwrap()),
            ItemKey::Role(RoleName::new("b").unwrap()),
            ItemKey::Service(ServiceName::new("a").unwrap()),
            ItemKey::Ban(node(1)),
            ItemKey::Issuer(Issuer::new("https://a")),
            ItemKey::Settings,
        ];
        assert!(keys.windows(2).all(|w| w[0] < w[1]), "{keys:?}");
    }

    #[test]
    fn key_display() {
        assert_eq!(
            ItemKey::Role(RoleName::new("oncall").unwrap()).to_string(),
            "role:oncall"
        );
        assert_eq!(
            ItemKey::Issuer(Issuer::new("https://idp")).to_string(),
            "issuer:https://idp"
        );
        assert_eq!(
            ItemKey::Ban(node(1)).to_string(),
            format!("ban:{}", node(1).hex())
        );
        assert_eq!(ItemKey::Settings.to_string(), "settings");
    }

    #[test]
    fn known_encodings() {
        let ban = Item::Ban {
            key: node(1),
            body: Ban { until: 5 },
        };
        assert_eq!(
            json(&ban),
            format!(
                r#"{{"body":{{"until":5}},"key":"{}","kind":"ban"}}"#,
                node(1).hex()
            )
        );
        let settings = Item::Settings {
            body: Settings::default(),
        };
        assert_eq!(
            json(&settings),
            r#"{"body":{"beat_secs":300,"fresh_secs":900,"freshness":"lenient"},"kind":"settings"}"#
        );
        let issuer = Item::Issuer {
            key: Issuer::new("https://idp"),
            body: IssuerConfig {
                client_id: Audience::new("cli"),
                audiences: vec![Audience::new("cli")],
            },
        };
        assert_eq!(
            json(&issuer),
            r#"{"body":{"audiences":["cli"],"client_id":"cli"},"key":"https://idp","kind":"issuer"}"#
        );
        let role = Item::Role {
            key: RoleName::new("staff").unwrap(),
            body: vec![Matcher::new("https://idp")],
        };
        assert_eq!(
            json(&role),
            r#"{"body":[{"issuer":"https://idp"}],"key":"staff","kind":"role"}"#
        );
    }

    #[test]
    fn items_know_their_keys() {
        let svc = Item::Service {
            key: ServiceName::new("status").unwrap(),
            body: Service {
                description: String::new(),
                allow: vec![],
                hosts: vec![],
                readers: vec![],
            },
        };
        assert_eq!(
            svc.key(),
            ItemKey::Service(ServiceName::new("status").unwrap())
        );
        let settings = Item::Settings {
            body: Settings::default(),
        };
        assert_eq!(settings.key(), ItemKey::Settings);
    }

    #[test]
    fn unknown_fields_and_kinds_are_refused() {
        for bad in [
            r#"{"kind":"ban","key":"00","body":{"until":1}}"#,
            r#"{"kind":"settings","body":{"beat_secs":1,"fresh_secs":1,"freshness":"lenient","x":1}}"#,
            r#"{"kind":"settings","key":"k","body":{"beat_secs":1,"fresh_secs":1,"freshness":"lenient"}}"#,
            r#"{"kind":"member","key":"x","body":{}}"#,
            r#"{"kind":"settings","body":{"beat_secs":1,"fresh_secs":1,"freshness":"sloppy"}}"#,
        ] {
            assert!(serde_json::from_str::<Item>(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn defaults() {
        let s = Settings::default();
        assert_eq!(s.freshness, FreshnessMode::Lenient);
        assert_eq!(s.beat_secs, DEFAULT_BEAT_SECS);
        assert_eq!(s.fresh_secs, DEFAULT_FRESH_SECS);
    }

    #[test]
    fn a_ban_holds_through_until() {
        let b = Ban { until: 100 };
        assert!(b.holds(99));
        assert!(b.holds(100));
        assert!(!b.holds(101));
    }

    proptest! {
        #[test]
        fn items_round_trip(seed in any::<u8>(), until in any::<i64>(), strict in any::<bool>()) {
            let items = [
                Item::Ban { key: node(seed), body: Ban { until } },
                Item::Settings {
                    body: Settings {
                        freshness: if strict { FreshnessMode::Strict } else { FreshnessMode::Lenient },
                        ..Settings::default()
                    },
                },
            ];
            for item in items {
                let back: Item = serde_json::from_slice(&canonical_bytes(&item).unwrap()).unwrap();
                prop_assert_eq!(back, item);
            }
        }

        #[test]
        fn key_round_trips(seed in any::<u8>()) {
            for key in [ItemKey::Ban(node(seed)), ItemKey::Settings] {
                let back: ItemKey = serde_json::from_str(&serde_json::to_string(&key).unwrap()).unwrap();
                prop_assert_eq!(back, key);
            }
        }
    }
}
