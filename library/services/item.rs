//! Policy items: what the root-signed policy is made of (card 36).
//!
//! The policy is a [head](crate::PolicyHead) over a sorted list of
//! [`Item`]s, one per role, service, banned node, banned person, trusted
//! issuer, and one for the fabric's settings. Each item is addressed by its [`ItemKey`] (kind, then
//! key), which is also the order the items are hashed in.
//!
//! The head signs an [`ItemsHash`](crate::ItemsHash) of the whole list. A
//! service item is also a [`SignedEntry`], signed by the root on its own, so
//! a caller can hold and check just the services it may use. Like every
//! signed body, items have no optional fields and refuse unknown ones.
//!
//! ```
//! use library::{Issuer, Item, ItemKey, NodeIdentity, Person};
//! let node = NodeIdentity::from_seed([2u8; 32]).node_id();
//! let ban = Item::Ban { key: node };
//! assert_eq!(ban.key(), ItemKey::Ban(node));
//! let eve = Person::new(Issuer::new("https://accounts.google.com"), "Eve@Example.com");
//! assert_eq!(eve.email(), "eve@example.com", "stored lowercase");
//! let removed = Item::PersonBan { key: eve.clone() };
//! assert_eq!(removed.key(), ItemKey::PersonBan(eve.clone()));
//! assert!(ItemKey::Ban(node) < ItemKey::PersonBan(eve), "sorted by kind, then key");
//! ```

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::entry::SignedEntry;
use crate::identity::NodeId;
use crate::idp::{Audience, Issuer, Principal};
use crate::registry::ServiceName;
use crate::role::{Matcher, RoleName};

/// Default [`Settings::beat_secs`]: a directory signs a new
/// [`Fresh`](crate::Fresh) every 5 minutes.
pub const DEFAULT_BEAT_SECS: u32 = 5 * 60;

/// Default [`Settings::fresh_secs`]: each [`Fresh`](crate::Fresh) is good for
/// 15 minutes (three missed beats).
pub const DEFAULT_FRESH_SECS: u32 = 15 * 60;

/// Where an item sits in the policy: its kind, then its key. The derived
/// order (kinds in declaration order, then the key's own order) is the order
/// the items are hashed in, and a key names at most one item.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", content = "key", rename_all = "snake_case")]
pub enum ItemKey {
    /// A role, by name.
    Role(RoleName),
    /// A service, by name.
    Service(ServiceName),
    /// A banned node, by its id.
    Ban(NodeId),
    /// A banned person, by issuer and email.
    PersonBan(Person),
    /// A trusted IdP, by its issuer identifier.
    Issuer(Issuer),
    /// The fabric's one settings item.
    Settings,
}

impl fmt::Display for ItemKey {
    /// `kind:key` (`settings` alone), for messages and traces.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ItemKey::Role(r) => write!(f, "role:{r}"),
            ItemKey::Service(s) => write!(f, "service:{s}"),
            ItemKey::Ban(n) => write!(f, "ban:{}", n.hex()),
            ItemKey::PersonBan(p) => write!(f, "person_ban:{p}"),
            ItemKey::Issuer(i) => write!(f, "issuer:{i}"),
            ItemKey::Settings => f.write_str("settings"),
        }
    }
}

/// A person, as a person ban names them: the exact issuer, and the email
/// that issuer verified, stored lowercase. Ordered by issuer, then email.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Person {
    /// The exact `iss` of the IdP that verifies them.
    pub issuer: Issuer,
    /// Their email, lowercase.
    pub email: String,
}

impl Person {
    /// The person `issuer` verifies as `email` (trimmed and lowercased here,
    /// so a ban matches whatever case the IdP reports).
    pub fn new(issuer: Issuer, email: &str) -> Person {
        Person {
            issuer,
            email: email.trim().to_ascii_lowercase(),
        }
    }

    /// Their email, lowercase.
    pub fn email(&self) -> &str {
        &self.email
    }

    /// Whether `principal` is this person: the same issuer, exactly, and a
    /// **verified** email equal to this one, ignoring ASCII case. A
    /// principal with no verified email is nobody's.
    ///
    /// ```
    /// use library::{Issuer, Person, Principal};
    /// let eve = Person::new(Issuer::new("https://idp"), "eve@example.com");
    /// let mut p = Principal {
    ///     issuer: "https://idp".into(), subject: "1".into(),
    ///     email: Some("EVE@example.com".into()), org: None, groups: vec![], not_after: 0,
    /// };
    /// assert!(eve.matches(&p));
    /// p.issuer = "https://other".into();
    /// assert!(!eve.matches(&p), "another issuer's eve is someone else");
    /// p.issuer = "https://idp".into();
    /// p.email = None;
    /// assert!(!eve.matches(&p));
    /// ```
    pub fn matches(&self, principal: &Principal) -> bool {
        principal.issuer == self.issuer.as_str()
            && principal
                .email
                .as_deref()
                .is_some_and(|e| e.eq_ignore_ascii_case(&self.email))
    }
}

impl fmt::Display for Person {
    /// `email (issuer)`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ({})", self.email, self.issuer)
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
        Settings {
            freshness: FreshnessMode::Lenient,
            beat_secs: DEFAULT_BEAT_SECS,
            fresh_secs: DEFAULT_FRESH_SECS,
        }
    }
}

/// One item of the policy: a kind, a key and a body. Serialized (and hashed)
/// as `{"kind": …, "key": …, "body": …}`; the settings item has no key, and
/// a service is its [`SignedEntry`]'s fields beside `"kind": "service"` (its
/// key is the entry's `name`).
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
    /// A service registry entry, signed by the root on its own.
    Service(SignedEntry),
    /// A removed node: refused everywhere until the admin restores it.
    Ban {
        /// The banned node.
        key: NodeId,
    },
    /// A removed person: refused by every host from any node, and cut an
    /// empty view by every directory, until the admin restores them.
    PersonBan {
        /// The banned person.
        key: Person,
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
    /// This item's [`ItemKey`]: its kind and key, its place in the policy.
    pub fn key(&self) -> ItemKey {
        match self {
            Item::Role { key, .. } => ItemKey::Role(key.clone()),
            Item::Service(entry) => ItemKey::Service(entry.name.clone()),
            Item::Ban { key } => ItemKey::Ban(*key),
            Item::PersonBan { key } => ItemKey::PersonBan(key.clone()),
            Item::Issuer { key, .. } => ItemKey::Issuer(key.clone()),
            Item::Settings { .. } => ItemKey::Settings,
        }
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
            ItemKey::PersonBan(Person::new(Issuer::new("https://a"), "a@x.com")),
            ItemKey::PersonBan(Person::new(Issuer::new("https://a"), "b@x.com")),
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
        let ban = Item::Ban { key: node(1) };
        assert_eq!(
            json(&ban),
            format!(r#"{{"key":"{}","kind":"ban"}}"#, node(1).hex())
        );
        let person = Item::PersonBan {
            key: Person::new(Issuer::new("https://idp"), "Eve@X.com"),
        };
        assert_eq!(
            json(&person),
            r#"{"key":{"email":"eve@x.com","issuer":"https://idp"},"kind":"person_ban"}"#
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

    fn service_item() -> Item {
        let root = NodeIdentity::from_seed([1u8; 32]);
        Item::Service(
            SignedEntry::sign(
                &root,
                crate::StateVersion(2),
                ServiceName::new("status").unwrap(),
                crate::Service {
                    description: String::new(),
                    allow: vec![],
                    hosts: vec![],
                },
            )
            .unwrap(),
        )
    }

    #[test]
    fn a_service_item_is_its_signed_entry() {
        let item = service_item();
        let text = json(&item);
        assert!(text.starts_with(r#"{"alg":"ed25519","fabric":""#), "{text}");
        assert!(
            text.contains(r#""kind":"service","name":"status","#),
            "{text}"
        );
        let back: Item = serde_json::from_str(&text).unwrap();
        assert_eq!(back, item);
        // An unknown field inside the entry is refused.
        let mut v: serde_json::Value = serde_json::from_str(&text).unwrap();
        v["extra"] = serde_json::json!(1);
        assert!(serde_json::from_value::<Item>(v).is_err());
    }

    #[test]
    fn items_know_their_keys() {
        let svc = service_item();
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
            r#"{"kind":"person_ban","key":{"issuer":"https://i","email":"e@x.com","x":1}}"#,
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

    proptest! {
        #[test]
        fn items_round_trip(seed in any::<u8>(), email in "[a-z]{1,8}@[a-z]{1,8}[.]com", strict in any::<bool>()) {
            let items = [
                Item::Ban { key: node(seed) },
                Item::PersonBan { key: Person::new(Issuer::new("https://idp"), &email) },
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
            let person = ItemKey::PersonBan(Person::new(Issuer::new("https://idp"), "e@x.com"));
            for key in [ItemKey::Ban(node(seed)), person, ItemKey::Settings] {
                let back: ItemKey = serde_json::from_str(&serde_json::to_string(&key).unwrap()).unwrap();
                prop_assert_eq!(back, key);
            }
        }
    }
}
