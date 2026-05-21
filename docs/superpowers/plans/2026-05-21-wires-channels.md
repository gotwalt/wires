# wires channels v1 — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the v1 channels layer atop the existing wires substrate. Named (operator-introduced, persistent name) and DM (DH-derived, zero-setup) variants share one wire vocabulary, one cap glob, and one `ChannelView` fold.

**Architecture:** Channels are a replay-derived view of a topic's log. Three new reserved message types in `wires-core`. DMs derive both topic_id (BLAKE3 over root+sorted pubkeys) and epoch key (BLAKE3 over X25519 DH) from the participant set — no on-wire key exchange. Named channels generate both randomly and use a sealed `__topic.history_grant` on invite. Member meta is mandatory; replay drops messages from unmeta'd publishers. All traffic flows through `wires-host` unchanged.

**Tech Stack:** Rust 2024 (toolchain stable, 1.95.0). snafu errors. redb 4 storage. iroh 0.98 + iroh-gossip 0.98 transport. blake3, ed25519-dalek 2, x25519-dalek 2. clap CLI. JSON-RPC MCP gateway.

**Spec:** `docs/superpowers/specs/2026-05-21-wires-channels-design.md` (commits `9a2ec45`, `ec05d01`, `3aefa9f`).

---

## File structure

### New files

| Path | Responsibility |
|---|---|
| `crates/wires-core/src/channel/mod.rs` | Re-exports: `ChannelView`, `ChannelVariant`, `MemberMeta`, `MemberKind`, schemas, derivation, replay. |
| `crates/wires-core/src/channel/types.rs` | `ChannelView`, `ChannelVariant`, `MemberMeta`, `MemberKind`. |
| `crates/wires-core/src/channel/schemas.rs` | Wire content schemas: `ChannelCreate`, `ChannelInvite`, `ChannelMemberMeta`. Type-string constants. |
| `crates/wires-core/src/channel/derive.rs` | DM topic_id + epoch-key derivation. |
| `crates/wires-core/src/channel/replay.rs` | Fold function over an ordered iterator of decrypted (sender, content) entries. |
| `crates/wires-node/src/channel.rs` | I/O wrapper: read a `TopicLog`, decrypt with the epoch key, drive the fold, produce a `ChannelView`. |
| `crates/wires-cli/src/cmd/channel.rs` | `wires channel create / list / members / invite` subcommands. |
| `crates/wires-cli/src/cmd/dm.rs` | `wires dm <pubkey>` and `wires dm list`. |
| `crates/wires-cli/src/cmd/me.rs` | `wires me set`. |
| `tests/wires-channels-it.rs` (in `crates/wires-cli/tests/`) | Integration tests across multiple wires-cli instances. |

### Modified files

| Path | Change |
|---|---|
| `crates/wires-core/src/lib.rs` | `pub mod channel;` + re-exports. |
| `crates/wires-core/src/reserved.rs:21` | Three new entries in `required_mode_for`. |
| `crates/wires-core/src/error.rs` | New error variants for channel-layer failures. |
| `crates/wires-node/src/lib.rs` | `pub mod channel;` + re-exports. |
| `crates/wires-cli/src/cmd/mod.rs` | Register `channel`, `dm`, `me` modules. |
| `crates/wires-cli/src/cmd/pair_approve.rs:60` | Always push `channels.**` to `cap_topics`. |
| `crates/wires-cli/src/cmd/publish_helpers.rs` | New helper `resolve_cap_for_topic` (auto-find a non-revoked cap covering a topic name). |
| `crates/wires-cli/src/main.rs` | New CLI subcommand enums + dispatch. |
| `crates/wires-mcp/src/mcp/tools.rs` | Six new tool descriptors in `list_descriptors()`, six handlers, six dispatch arms in `call()`. |

---

## Conventions for every task

- **snafu errors only.** Every new error variant carries `#[snafu(implicit)] location: Location`, no `message: String` field, display strings end with `, at {location}`. Pattern: see `crates/wires-core/src/error.rs` and the rule in `CLAUDE.md`.
- **TDD.** Write the test, run it to confirm RED, write minimal code to pass, run again to confirm GREEN, commit.
- **`cargo fmt --all && cargo clippy --workspace -- -D warnings && cargo test --workspace`** must pass before each commit.
- **Commits.** One commit per task; message in conventional-commit style. End each commit message with the trailer:
  ```
  Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
  ```
- **Latest-stable deps.** No new dependencies should be needed — `blake3`, `x25519-dalek`, `ed25519-dalek`, `rand_core`, `serde`, `serde_json`, `snafu` are all already in the workspace.

---

## Task 1: Stub the `wires-core::channel` module and re-exports

**Files:**
- Create: `crates/wires-core/src/channel/mod.rs`
- Create: `crates/wires-core/src/channel/types.rs` (placeholder)
- Modify: `crates/wires-core/src/lib.rs`

- [ ] **Step 1: Write the failing test**

Add to a new file `crates/wires-core/tests/channel_module_present.rs`:

```rust
#[test]
fn channel_module_exposes_marker() {
    // Smoke test: the module exists and exposes a marker constant.
    assert_eq!(wires_core::channel::MODULE_VERSION, 1);
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p wires-core channel_module_exposes_marker`
Expected: FAIL with `unresolved import wires_core::channel`.

- [ ] **Step 3: Create the stub files**

`crates/wires-core/src/channel/mod.rs`:

```rust
//! Channel layer over the substrate. Spec:
//! docs/superpowers/specs/2026-05-21-wires-channels-design.md

pub mod types;

/// Version stamp for the channel-layer wire vocabulary. Bumped only when
/// breaking schema changes ship.
pub const MODULE_VERSION: u32 = 1;
```

`crates/wires-core/src/channel/types.rs`:

```rust
//! Channel view, variant, member metadata types. Spec §4.
```

Add to `crates/wires-core/src/lib.rs` after the existing `pub mod` declarations:

```rust
pub mod channel;
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p wires-core channel_module_exposes_marker`
Expected: PASS.

- [ ] **Step 5: Confirm workspace still builds**

Run: `cargo build --workspace`
Expected: success.

- [ ] **Step 6: Commit**

```bash
git add crates/wires-core/src/channel/ crates/wires-core/src/lib.rs crates/wires-core/tests/channel_module_present.rs
git commit -m "$(cat <<'EOF'
core(channel): scaffold channel module

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

---

## Task 2: Add the three reserved message types

**Files:**
- Modify: `crates/wires-core/src/reserved.rs`

- [ ] **Step 1: Write the failing test**

Append to the existing `#[cfg(test)] mod tests` in `crates/wires-core/src/reserved.rs`:

```rust
#[test]
fn channel_create_requires_public() {
    check_kind_matches("__channel.create", &MessageKind::Public).unwrap();
    assert!(check_kind_matches("__channel.create", &MessageKind::Standard).is_err());
    assert!(check_kind_matches("__channel.create", &MessageKind::SealedTo([0u8; 32])).is_err());
}

#[test]
fn channel_invite_requires_public() {
    check_kind_matches("__channel.invite", &MessageKind::Public).unwrap();
    assert!(check_kind_matches("__channel.invite", &MessageKind::Standard).is_err());
}

#[test]
fn channel_member_meta_requires_public() {
    check_kind_matches("__channel.member_meta", &MessageKind::Public).unwrap();
    assert!(check_kind_matches("__channel.member_meta", &MessageKind::Standard).is_err());
}

#[test]
fn channel_types_are_reserved() {
    assert!(is_reserved("__channel.create"));
    assert!(is_reserved("__channel.invite"));
    assert!(is_reserved("__channel.member_meta"));
    assert!(!is_reserved("__channel.unknown"));
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p wires-core reserved::tests::channel_`
Expected: FAIL — `check_kind_matches` returns Ok for unknown reserved types and the assertions about `is_reserved` are false.

- [ ] **Step 3: Add three arms to `required_mode_for`**

Modify `crates/wires-core/src/reserved.rs` in the `required_mode_for` match (around line 22) — add the three arms before the catch-all `_ => None`:

```rust
"__channel.create" => Some(RequiredMode::Public),
"__channel.invite" => Some(RequiredMode::Public),
"__channel.member_meta" => Some(RequiredMode::Public),
```

Also update the doc comment block above the function to list them.

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p wires-core reserved::`
Expected: PASS (all reserved-type tests, including the new ones and the existing ones).

- [ ] **Step 5: Commit**

```bash
git add crates/wires-core/src/reserved.rs
git commit -m "$(cat <<'EOF'
core(reserved): add __channel.create / .invite / .member_meta

Three new reserved types, all Public mode. Roster state must be replayable
by every reader, so the channel-event vocabulary cannot be sealed.

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

---

## Task 3: `MemberKind` enum + serde round-trip

**Files:**
- Modify: `crates/wires-core/src/channel/types.rs`

- [ ] **Step 1: Write the failing test**

Replace the placeholder content of `crates/wires-core/src/channel/types.rs` with:

```rust
//! Channel view, variant, member metadata types. Spec §4.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MemberKind {
    Agent,
    Api,
    Cli,
    Human,
    Unknown,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn member_kind_serializes_snake_case() {
        let cases = [
            (MemberKind::Agent, "\"agent\""),
            (MemberKind::Api, "\"api\""),
            (MemberKind::Cli, "\"cli\""),
            (MemberKind::Human, "\"human\""),
            (MemberKind::Unknown, "\"unknown\""),
        ];
        for (v, expected) in cases {
            let s = serde_json::to_string(&v).unwrap();
            assert_eq!(s, expected);
            let parsed: MemberKind = serde_json::from_str(&s).unwrap();
            assert_eq!(parsed, v);
        }
    }

    #[test]
    fn member_kind_rejects_unknown_string() {
        let r: serde_json::Result<MemberKind> = serde_json::from_str("\"bot\"");
        assert!(r.is_err(), "unknown variant should fail to parse");
    }
}
```

- [ ] **Step 2: Run tests**

Run: `cargo test -p wires-core channel::types::tests`
Expected: PASS.

- [ ] **Step 3: Commit**

```bash
git add crates/wires-core/src/channel/types.rs
git commit -m "$(cat <<'EOF'
core(channel): add MemberKind enum

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

---

## Task 4: `MemberMeta` struct + `ChannelVariant` + `ChannelView`

**Files:**
- Modify: `crates/wires-core/src/channel/types.rs`

- [ ] **Step 1: Add the type definitions**

Append to `crates/wires-core/src/channel/types.rs`:

```rust
use std::collections::{BTreeMap, BTreeSet};

use crate::wire::{Pubkey, TopicId};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemberMeta {
    pub kind: MemberKind,
    pub display_name: String,
    pub description: Option<String>,
    pub asserted_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChannelVariant {
    Named {
        name: String,
        description: Option<String>,
    },
    Dm {
        /// Sorted byte-lexicographically.
        participants: Vec<Pubkey>,
    },
}

#[derive(Debug, Clone)]
pub struct ChannelView {
    pub topic_id: TopicId,
    pub variant: ChannelVariant,
    /// Full members: have on-log `__channel.member_meta`.
    pub members: BTreeMap<Pubkey, MemberMeta>,
    /// Invited but not yet meta'd. Only populated for Named channels.
    pub pending: BTreeSet<Pubkey>,
    /// Some only for Named.
    pub created_at: Option<i64>,
    /// Some only for Named. Display/audit only — no policy role (spec §3).
    pub creator: Option<Pubkey>,
}

impl ChannelView {
    /// Construct an empty Named-variant view for `topic_id` before any log
    /// entries have been folded.
    pub fn empty_named(topic_id: TopicId) -> Self {
        Self {
            topic_id,
            variant: ChannelVariant::Named {
                name: String::new(),
                description: None,
            },
            members: BTreeMap::new(),
            pending: BTreeSet::new(),
            created_at: None,
            creator: None,
        }
    }

    /// Construct an empty DM view from a sorted participant list. Caller is
    /// responsible for verifying the participants match `topic_id` per the
    /// derivation in `derive::dm_topic_id`.
    pub fn empty_dm(topic_id: TopicId, participants: Vec<Pubkey>) -> Self {
        Self {
            topic_id,
            variant: ChannelVariant::Dm { participants },
            members: BTreeMap::new(),
            pending: BTreeSet::new(),
            created_at: None,
            creator: None,
        }
    }
}
```

Also re-export from `crates/wires-core/src/channel/mod.rs`:

```rust
pub use types::{ChannelVariant, ChannelView, MemberKind, MemberMeta};
```

- [ ] **Step 2: Add a smoke test**

Append to the existing `mod tests` block in `types.rs`:

```rust
#[test]
fn empty_named_has_empty_roster() {
    let v = ChannelView::empty_named([7u8; 32]);
    assert!(v.members.is_empty());
    assert!(v.pending.is_empty());
    assert_eq!(v.topic_id, [7u8; 32]);
    assert!(matches!(v.variant, ChannelVariant::Named { .. }));
}

#[test]
fn empty_dm_carries_sorted_participants() {
    let alice = [1u8; 32];
    let bob = [2u8; 32];
    let v = ChannelView::empty_dm([0u8; 32], vec![alice, bob]);
    if let ChannelVariant::Dm { participants } = &v.variant {
        assert_eq!(participants, &vec![alice, bob]);
    } else {
        panic!("expected Dm variant");
    }
}

#[test]
fn member_meta_round_trips() {
    let m = MemberMeta {
        kind: MemberKind::Agent,
        display_name: "kitchen-bot".to_string(),
        description: Some("monitors the fridge".to_string()),
        asserted_at: 1_000,
    };
    let s = serde_json::to_string(&m).unwrap();
    let back: MemberMeta = serde_json::from_str(&s).unwrap();
    assert_eq!(back, m);
}
```

- [ ] **Step 3: Run tests**

Run: `cargo test -p wires-core channel::`
Expected: PASS for the new tests.

- [ ] **Step 4: Commit**

```bash
git add crates/wires-core/src/channel/
git commit -m "$(cat <<'EOF'
core(channel): add ChannelView, ChannelVariant, MemberMeta types

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

---

## Task 5: Wire content schemas + type-string constants

**Files:**
- Create: `crates/wires-core/src/channel/schemas.rs`
- Modify: `crates/wires-core/src/channel/mod.rs`

- [ ] **Step 1: Write the failing test**

Create `crates/wires-core/src/channel/schemas.rs`:

```rust
//! Wire content schemas for the three channel reserved types. Spec §6.

use serde::{Deserialize, Serialize};

use crate::channel::types::MemberKind;
use crate::wire::Pubkey;

pub const TYPE_CREATE: &str = "__channel.create";
pub const TYPE_INVITE: &str = "__channel.invite";
pub const TYPE_MEMBER_META: &str = "__channel.member_meta";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChannelCreate {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub created_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChannelInvite {
    #[serde(with = "hex::serde")]
    pub agent: Pubkey,
    pub invited_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChannelMemberMeta {
    pub kind: MemberKind,
    pub display_name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub asserted_at: i64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn channel_create_round_trips() {
        let v = ChannelCreate {
            name: "coordinate-grocery".to_string(),
            description: Some("weekly shop".to_string()),
            created_at: 1_700_000_000_000,
        };
        let s = serde_json::to_string(&v).unwrap();
        let back: ChannelCreate = serde_json::from_str(&s).unwrap();
        assert_eq!(back, v);
    }

    #[test]
    fn channel_create_without_description_omits_field() {
        let v = ChannelCreate {
            name: "x".to_string(),
            description: None,
            created_at: 1,
        };
        let s = serde_json::to_string(&v).unwrap();
        assert!(!s.contains("description"));
    }

    #[test]
    fn channel_invite_round_trips() {
        let v = ChannelInvite {
            agent: [9u8; 32],
            invited_at: 100,
        };
        let s = serde_json::to_string(&v).unwrap();
        let back: ChannelInvite = serde_json::from_str(&s).unwrap();
        assert_eq!(back, v);
    }

    #[test]
    fn member_meta_content_round_trips() {
        let v = ChannelMemberMeta {
            kind: MemberKind::Api,
            display_name: "gmail-bridge".to_string(),
            description: None,
            asserted_at: 42,
        };
        let s = serde_json::to_string(&v).unwrap();
        let back: ChannelMemberMeta = serde_json::from_str(&s).unwrap();
        assert_eq!(back, v);
    }
}
```

Re-export from `crates/wires-core/src/channel/mod.rs`:

```rust
pub mod schemas;
pub use schemas::{
    ChannelCreate, ChannelInvite, ChannelMemberMeta, TYPE_CREATE, TYPE_INVITE, TYPE_MEMBER_META,
};
```

- [ ] **Step 2: Run tests**

Run: `cargo test -p wires-core channel::schemas`
Expected: PASS.

- [ ] **Step 3: Commit**

```bash
git add crates/wires-core/src/channel/
git commit -m "$(cat <<'EOF'
core(channel): add wire content schemas

Three Public schemas: ChannelCreate, ChannelInvite, ChannelMemberMeta,
plus type-string constants.

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

---

## Task 6: DM topic_id derivation

**Files:**
- Create: `crates/wires-core/src/channel/derive.rs`
- Modify: `crates/wires-core/src/channel/mod.rs`

- [ ] **Step 1: Write the failing tests**

Create `crates/wires-core/src/channel/derive.rs`:

```rust
//! DM topic_id and epoch-key derivation. Spec §5.

use crate::wire::{Pubkey, TopicId};

const TOPIC_DOMAIN: &[u8] = b"wires.dm.v1\0";
const EPOCH_DOMAIN: &[u8] = b"wires.dm.epoch.v1\0";

/// Returns a sorted clone of `participants` (byte-lexicographic).
pub fn sort_participants(mut participants: Vec<Pubkey>) -> Vec<Pubkey> {
    participants.sort();
    participants
}

/// Compute the DM topic_id per spec §5.1:
///   BLAKE3("wires.dm.v1\0" || root_pubkey || "\0" || sorted_pubkey_concat)
pub fn dm_topic_id(root: &Pubkey, sorted_participants: &[Pubkey]) -> TopicId {
    let mut hasher = blake3::Hasher::new();
    hasher.update(TOPIC_DOMAIN);
    hasher.update(root);
    hasher.update(b"\0");
    for pk in sorted_participants {
        hasher.update(pk);
    }
    *hasher.finalize().as_bytes()
}

/// Build the canonical name string used for cap-glob matching on a DM topic.
/// Format: `channels.dm.<hex(topic_id)>`. Falls under the broad `channels.**`
/// glob without needing a separate prefix.
pub fn dm_topic_name(topic_id: &TopicId) -> String {
    format!("channels.dm.{}", hex::encode(topic_id))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dm_topic_id_is_independent_of_input_order() {
        let alice: Pubkey = [1u8; 32];
        let bob: Pubkey = [2u8; 32];
        let root: Pubkey = [9u8; 32];
        let a = dm_topic_id(&root, &sort_participants(vec![alice, bob]));
        let b = dm_topic_id(&root, &sort_participants(vec![bob, alice]));
        assert_eq!(a, b);
    }

    #[test]
    fn dm_topic_id_distinct_per_household() {
        let alice: Pubkey = [1u8; 32];
        let bob: Pubkey = [2u8; 32];
        let participants = sort_participants(vec![alice, bob]);
        let id_a = dm_topic_id(&[7u8; 32], &participants);
        let id_b = dm_topic_id(&[8u8; 32], &participants);
        assert_ne!(id_a, id_b, "different roots must yield different topic ids");
    }

    #[test]
    fn dm_topic_id_distinct_per_participant_set() {
        let alice: Pubkey = [1u8; 32];
        let bob: Pubkey = [2u8; 32];
        let carol: Pubkey = [3u8; 32];
        let root: Pubkey = [9u8; 32];
        let id_ab = dm_topic_id(&root, &sort_participants(vec![alice, bob]));
        let id_ac = dm_topic_id(&root, &sort_participants(vec![alice, carol]));
        assert_ne!(id_ab, id_ac);
    }

    #[test]
    fn dm_topic_name_is_under_channels_glob() {
        use crate::cap::glob_matches;
        let id: TopicId = [0xab; 32];
        let name = dm_topic_name(&id);
        assert!(glob_matches("channels.**", &name).unwrap());
    }
}
```

Add to `crates/wires-core/src/channel/mod.rs`:

```rust
pub mod derive;
pub use derive::{dm_topic_id, dm_topic_name, sort_participants};
```

- [ ] **Step 2: Run tests**

Run: `cargo test -p wires-core channel::derive`
Expected: PASS.

- [ ] **Step 3: Commit**

```bash
git add crates/wires-core/src/channel/
git commit -m "$(cat <<'EOF'
core(channel): DM topic_id derivation + name helper

BLAKE3('wires.dm.v1\\0' || root || '\\0' || sorted_pubkeys). Name is
channels.dm.<hex(topic_id)>, falling under the broad channels.** glob.

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

---

## Task 7: DM epoch-key derivation (X25519 DH)

**Files:**
- Modify: `crates/wires-core/src/channel/derive.rs`

- [ ] **Step 1: Add the function and tests**

Append to `crates/wires-core/src/channel/derive.rs`:

```rust
/// 32-byte symmetric AEAD key.
pub type EpochKey = [u8; 32];

/// Compute the DM epoch key per spec §5.2.
///
/// ```text
/// shared = X25519(self_x25519_sk, other_x25519_pk)
/// epoch_key = BLAKE3(shared || "wires.dm.epoch.v1\0" || root || sorted_pubkey_concat)
/// ```
///
/// Both DM participants arrive at the same key by passing the other side's
/// public key in as `other_x25519_pk`; X25519 is commutative.
pub fn dm_epoch_key(
    self_x25519_sk: &[u8; 32],
    other_x25519_pk: &[u8; 32],
    root: &Pubkey,
    sorted_participants: &[Pubkey],
) -> EpochKey {
    let sk = x25519_dalek::StaticSecret::from(*self_x25519_sk);
    let pk = x25519_dalek::PublicKey::from(*other_x25519_pk);
    let shared = sk.diffie_hellman(&pk);

    let mut hasher = blake3::Hasher::new();
    hasher.update(shared.as_bytes());
    hasher.update(EPOCH_DOMAIN);
    hasher.update(root);
    for pk in sorted_participants {
        hasher.update(pk);
    }
    *hasher.finalize().as_bytes()
}
```

Append to the `#[cfg(test)] mod tests` block:

```rust
#[test]
fn dm_epoch_key_is_commutative() {
    // Two random x25519 keypairs, same root, same participants.
    use rand_core::OsRng;
    use x25519_dalek::{PublicKey, StaticSecret};

    let alice_sk = StaticSecret::random_from_rng(OsRng);
    let bob_sk = StaticSecret::random_from_rng(OsRng);
    let alice_pk_bytes: [u8; 32] = PublicKey::from(&alice_sk).to_bytes();
    let bob_pk_bytes: [u8; 32] = PublicKey::from(&bob_sk).to_bytes();
    let alice_sk_bytes = alice_sk.to_bytes();
    let bob_sk_bytes = bob_sk.to_bytes();

    let root: Pubkey = [9u8; 32];
    // Use ed25519-shaped pubkeys for the derivation (different from the
    // x25519 pubkeys used in DH — the participants are identified by their
    // ed25519 identities).
    let participants = sort_participants(vec![[1u8; 32], [2u8; 32]]);

    let alice_key = dm_epoch_key(&alice_sk_bytes, &bob_pk_bytes, &root, &participants);
    let bob_key = dm_epoch_key(&bob_sk_bytes, &alice_pk_bytes, &root, &participants);
    assert_eq!(alice_key, bob_key, "X25519 commutativity must yield identical keys");
}

#[test]
fn dm_epoch_key_distinct_per_root() {
    use rand_core::OsRng;
    use x25519_dalek::{PublicKey, StaticSecret};
    let alice_sk = StaticSecret::random_from_rng(OsRng);
    let bob_sk = StaticSecret::random_from_rng(OsRng);
    let alice_sk_bytes = alice_sk.to_bytes();
    let bob_pk_bytes: [u8; 32] = PublicKey::from(&bob_sk).to_bytes();
    let participants = sort_participants(vec![[1u8; 32], [2u8; 32]]);

    let key_a = dm_epoch_key(&alice_sk_bytes, &bob_pk_bytes, &[7u8; 32], &participants);
    let key_b = dm_epoch_key(&alice_sk_bytes, &bob_pk_bytes, &[8u8; 32], &participants);
    assert_ne!(key_a, key_b);
}
```

Re-export from `mod.rs`:

```rust
pub use derive::{dm_epoch_key, EpochKey};
```

- [ ] **Step 2: Confirm `x25519-dalek` is available for `wires-core`**

Run: `grep '^x25519' crates/wires-core/Cargo.toml`
If empty, add to `crates/wires-core/Cargo.toml` under `[dependencies]`:

```toml
x25519-dalek = { workspace = true }
rand_core = { workspace = true }
```

(Both are already used by `wires-node` and `wires-cli`; `wires-core` did not previously need them.)

- [ ] **Step 3: Run tests**

Run: `cargo test -p wires-core channel::derive`
Expected: PASS, including both commutativity and root-distinctness tests.

- [ ] **Step 4: Commit**

```bash
git add crates/wires-core/
git commit -m "$(cat <<'EOF'
core(channel): DM epoch-key derivation via X25519 DH

Both parties compute BLAKE3(X25519(self_sk, other_pk) || domain || root ||
sorted_pubkeys) independently; commutativity yields identical keys without
any on-wire exchange.

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

---

## Task 8: Replay fold — scaffold + empty-log case

**Files:**
- Create: `crates/wires-core/src/channel/replay.rs`
- Modify: `crates/wires-core/src/channel/mod.rs`

- [ ] **Step 1: Create the replay module with a base test**

Create `crates/wires-core/src/channel/replay.rs`:

```rust
//! Channel-event replay-fold. Spec §7.
//!
//! The fold consumes an ordered iterator of `(sender, content_type, content_bytes)`
//! tuples produced by the substrate layer after envelope-verification and decrypt.
//! It is pure: same input sequence → same `ChannelView` regardless of how many
//! times you call it.

use crate::channel::schemas::{
    ChannelCreate, ChannelInvite, ChannelMemberMeta, TYPE_CREATE, TYPE_INVITE, TYPE_MEMBER_META,
};
use crate::channel::types::{ChannelVariant, ChannelView, MemberMeta};
use crate::wire::Pubkey;

/// One decoded channel-layer event the fold can consume. Sender comes from
/// the envelope; `content_type` and `data` come from `CanonicalContent`.
#[derive(Debug, Clone)]
pub struct Event {
    pub sender: Pubkey,
    pub content_type: String,
    /// The structured payload from `CanonicalContent::data`. None means the
    /// publisher omitted it (channel events without payloads are rejected at
    /// fold time by the per-rule decoders).
    pub data: Option<serde_json::Value>,
}

/// Fold `events` into `view`. Events arrive in substrate order: per-publisher
/// hash-chain ordered, ingest-order across publishers. Events that violate
/// state-machine rules are dropped silently — the fold does not return errors.
pub fn fold(view: &mut ChannelView, events: impl IntoIterator<Item = Event>) {
    for ev in events {
        apply(view, &ev);
    }
}

fn apply(_view: &mut ChannelView, _ev: &Event) {
    // Filled in by subsequent tasks. Placeholder for the rules.
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_log_yields_empty_view() {
        let mut v = ChannelView::empty_named([1u8; 32]);
        fold(&mut v, std::iter::empty());
        assert!(v.members.is_empty());
        assert!(v.pending.is_empty());
        assert_eq!(v.created_at, None);
        assert_eq!(v.creator, None);
    }

    #[test]
    fn fold_is_idempotent_under_double_replay() {
        let mut v = ChannelView::empty_named([1u8; 32]);
        let events = vec![];
        fold(&mut v.clone(), events.clone());
        fold(&mut v, events);
        // Trivial for empty; later tasks add meaningful cases.
        assert_eq!(v.members.len(), 0);
    }
}
```

Make `ChannelView` derive `Clone` — it already does per Task 4 — and add to `mod.rs`:

```rust
pub mod replay;
pub use replay::{fold, Event};
```

- [ ] **Step 2: Run tests**

Run: `cargo test -p wires-core channel::replay`
Expected: PASS.

- [ ] **Step 3: Commit**

```bash
git add crates/wires-core/src/channel/
git commit -m "$(cat <<'EOF'
core(channel): scaffold replay fold

Empty-log case + idempotence; per-rule arms filled in by subsequent tasks.

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

---

## Task 9: Replay fold — rule 1 (`__channel.create`)

**Files:**
- Modify: `crates/wires-core/src/channel/replay.rs`

- [ ] **Step 1: Write the failing test**

Append to the `mod tests` block:

```rust
fn ev(sender: Pubkey, type_: &str, content: &impl serde::Serialize) -> Event {
    Event {
        sender,
        content_type: type_.to_string(),
        data: Some(serde_json::to_value(content).unwrap()),
    }
}

#[test]
fn first_channel_create_sets_name_and_creator() {
    let alice: Pubkey = [1u8; 32];
    let mut v = ChannelView::empty_named([7u8; 32]);
    fold(
        &mut v,
        [ev(
            alice,
            TYPE_CREATE,
            &ChannelCreate {
                name: "coord".to_string(),
                description: Some("d".to_string()),
                created_at: 100,
            },
        )],
    );
    assert_eq!(v.creator, Some(alice));
    assert_eq!(v.created_at, Some(100));
    if let ChannelVariant::Named { name, description } = &v.variant {
        assert_eq!(name, "coord");
        assert_eq!(description.as_deref(), Some("d"));
    } else {
        panic!("expected Named variant");
    }
}

#[test]
fn second_channel_create_is_ignored() {
    let alice: Pubkey = [1u8; 32];
    let bob: Pubkey = [2u8; 32];
    let mut v = ChannelView::empty_named([7u8; 32]);
    fold(
        &mut v,
        [
            ev(
                alice,
                TYPE_CREATE,
                &ChannelCreate {
                    name: "first".to_string(),
                    description: None,
                    created_at: 100,
                },
            ),
            ev(
                bob,
                TYPE_CREATE,
                &ChannelCreate {
                    name: "second".to_string(),
                    description: None,
                    created_at: 200,
                },
            ),
        ],
    );
    assert_eq!(v.creator, Some(alice));
    if let ChannelVariant::Named { name, .. } = &v.variant {
        assert_eq!(name, "first");
    } else {
        panic!("expected Named variant");
    }
}

#[test]
fn channel_create_on_dm_topic_is_rejected() {
    let alice: Pubkey = [1u8; 32];
    let bob: Pubkey = [2u8; 32];
    let mut v = ChannelView::empty_dm([7u8; 32], vec![alice, bob]);
    fold(
        &mut v,
        [ev(
            alice,
            TYPE_CREATE,
            &ChannelCreate {
                name: "x".to_string(),
                description: None,
                created_at: 1,
            },
        )],
    );
    assert_eq!(v.creator, None);
    if let ChannelVariant::Dm { .. } = v.variant {
        // good
    } else {
        panic!("expected Dm variant preserved");
    }
}
```

- [ ] **Step 2: Run tests to confirm RED**

Run: `cargo test -p wires-core channel::replay`
Expected: FAIL — the three new tests fail because `apply` is a no-op.

- [ ] **Step 3: Implement rule 1**

Replace the empty `apply` body with:

```rust
fn apply(view: &mut ChannelView, ev: &Event) {
    match ev.content_type.as_str() {
        TYPE_CREATE => apply_create(view, ev),
        _ => {}
    }
}

fn apply_create(view: &mut ChannelView, ev: &Event) {
    // Rule 2: DM topics reject __channel.create.
    if matches!(view.variant, ChannelVariant::Dm { .. }) {
        return;
    }
    // Rule 1: first create wins.
    if view.creator.is_some() {
        return;
    }
    let parsed: ChannelCreate = match ev.data.as_ref().and_then(|d| serde_json::from_value(d.clone()).ok()) {
        Some(v) => v,
        None => return, // missing or malformed payload — drop
    };
    view.variant = ChannelVariant::Named {
        name: parsed.name,
        description: parsed.description,
    };
    view.creator = Some(ev.sender);
    view.created_at = Some(parsed.created_at);
}
```

Note: the spec says rule 1 also requires the publisher's cap to cover the topic with Read+Write — that check is upstream (the wires-node wrapper passes only envelopes whose cap is already valid; an envelope whose cap doesn't cover the topic never reaches the fold). The fold itself doesn't carry the cap table.

- [ ] **Step 4: Run tests to confirm GREEN**

Run: `cargo test -p wires-core channel::replay`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/wires-core/src/channel/replay.rs
git commit -m "$(cat <<'EOF'
core(channel): fold rule 1 — __channel.create (Named topics only)

First create wins; DM topics reject creates (roster is derivation).

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

---

## Task 10: Replay fold — rules 3+4+5 (member_meta mandatory, self-only, latest-wins)

**Files:**
- Modify: `crates/wires-core/src/channel/replay.rs`

- [ ] **Step 1: Write the failing tests**

Append to `mod tests`:

```rust
#[test]
fn member_meta_self_publish_admits_into_members() {
    let alice: Pubkey = [1u8; 32];
    let mut v = ChannelView::empty_named([7u8; 32]);
    fold(
        &mut v,
        [ev(
            alice,
            TYPE_MEMBER_META,
            &ChannelMemberMeta {
                kind: MemberKind::Agent,
                display_name: "alice-bot".to_string(),
                description: None,
                asserted_at: 5,
            },
        )],
    );
    assert!(v.members.contains_key(&alice));
}

#[test]
fn member_meta_latest_wins() {
    let alice: Pubkey = [1u8; 32];
    let mut v = ChannelView::empty_named([7u8; 32]);
    fold(
        &mut v,
        [
            ev(
                alice,
                TYPE_MEMBER_META,
                &ChannelMemberMeta {
                    kind: MemberKind::Agent,
                    display_name: "old".to_string(),
                    description: None,
                    asserted_at: 5,
                },
            ),
            ev(
                alice,
                TYPE_MEMBER_META,
                &ChannelMemberMeta {
                    kind: MemberKind::Agent,
                    display_name: "new".to_string(),
                    description: None,
                    asserted_at: 10,
                },
            ),
        ],
    );
    assert_eq!(v.members[&alice].display_name, "new");
}

#[test]
fn pre_meta_events_from_publisher_are_dropped() {
    // alice tries to invite bob before publishing her own member_meta.
    // The invite should not be folded.
    let alice: Pubkey = [1u8; 32];
    let bob: Pubkey = [2u8; 32];
    let mut v = ChannelView::empty_named([7u8; 32]);
    fold(
        &mut v,
        [
            ev(
                alice,
                TYPE_CREATE,
                &ChannelCreate {
                    name: "c".to_string(),
                    description: None,
                    created_at: 1,
                },
            ),
            // No alice member_meta yet.
            ev(
                alice,
                TYPE_INVITE,
                &ChannelInvite {
                    agent: bob,
                    invited_at: 2,
                },
            ),
        ],
    );
    assert!(v.pending.is_empty(), "invite from unmeta'd publisher must be dropped");
}
```

Update imports in the test module to include `MemberKind`:

```rust
use crate::channel::types::MemberKind;
```

- [ ] **Step 2: Run tests to confirm RED**

Run: `cargo test -p wires-core channel::replay`
Expected: the three new tests fail.

- [ ] **Step 3: Implement rules 3+4+5**

Replace `apply` and add helpers:

```rust
fn apply(view: &mut ChannelView, ev: &Event) {
    match ev.content_type.as_str() {
        TYPE_CREATE => apply_create(view, ev),
        TYPE_MEMBER_META => apply_member_meta(view, ev),
        // INVITE arm added in next task
        _ => {}
    }
}

fn apply_member_meta(view: &mut ChannelView, ev: &Event) {
    // Rule 4: self-only. The publisher's pubkey IS the subject; there is no
    // explicit subject field in the content. So self-only is satisfied by
    // construction — we apply the meta to `ev.sender` only.
    let parsed: ChannelMemberMeta = match ev.data.as_ref().and_then(|d| serde_json::from_value(d.clone()).ok()) {
        Some(v) => v,
        None => return,
    };
    let meta = MemberMeta {
        kind: parsed.kind,
        display_name: parsed.display_name,
        description: parsed.description,
        asserted_at: parsed.asserted_at,
    };
    // Rule 5: latest-wins (BTreeMap insert overwrites).
    view.members.insert(ev.sender, meta);
    // Promote from pending if applicable.
    view.pending.remove(&ev.sender);
}

/// Rule 3: returns true iff `sender` has already published a member_meta on
/// this view. `__channel.member_meta` itself is exempt — it is its own
/// admission ticket.
fn publisher_has_meta(view: &ChannelView, sender: &Pubkey) -> bool {
    view.members.contains_key(sender)
}
```

Now wrap `apply` so that for every non-`member_meta` event the publisher must already be in `members`. Replace `apply` with:

```rust
fn apply(view: &mut ChannelView, ev: &Event) {
    let is_meta = ev.content_type == TYPE_MEMBER_META;
    if !is_meta && !publisher_has_meta(view, &ev.sender) {
        // Rule 3: drop messages from publishers with no on-log meta.
        // Exception: __channel.create is also exempt — it is the bootstrap
        // event that the creator publishes immediately before their own meta;
        // its only effect is on `name/creator/created_at`, none of which
        // depend on the publisher being a "member."
        if ev.content_type != TYPE_CREATE {
            return;
        }
    }
    match ev.content_type.as_str() {
        TYPE_CREATE => apply_create(view, ev),
        TYPE_MEMBER_META => apply_member_meta(view, ev),
        _ => {}
    }
}
```

- [ ] **Step 4: Run tests to confirm GREEN**

Run: `cargo test -p wires-core channel::replay`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/wires-core/src/channel/replay.rs
git commit -m "$(cat <<'EOF'
core(channel): fold rules 3+4+5 — member_meta mandatory, self-only, latest-wins

Members admitted only via their own __channel.member_meta. Subsequent meta
overwrites. Non-create/non-meta events from publishers with no on-log meta
are dropped.

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

---

## Task 11: Replay fold — rule 6 (`__channel.invite` + pending)

**Files:**
- Modify: `crates/wires-core/src/channel/replay.rs`

- [ ] **Step 1: Write the failing tests**

Append:

```rust
#[test]
fn invite_from_full_member_places_agent_in_pending() {
    let alice: Pubkey = [1u8; 32];
    let bob: Pubkey = [2u8; 32];
    let mut v = ChannelView::empty_named([7u8; 32]);
    fold(
        &mut v,
        [
            ev(
                alice,
                TYPE_CREATE,
                &ChannelCreate {
                    name: "c".to_string(),
                    description: None,
                    created_at: 1,
                },
            ),
            ev(
                alice,
                TYPE_MEMBER_META,
                &ChannelMemberMeta {
                    kind: MemberKind::Agent,
                    display_name: "alice".to_string(),
                    description: None,
                    asserted_at: 2,
                },
            ),
            ev(
                alice,
                TYPE_INVITE,
                &ChannelInvite {
                    agent: bob,
                    invited_at: 3,
                },
            ),
        ],
    );
    assert!(v.pending.contains(&bob));
    assert!(!v.members.contains_key(&bob));
}

#[test]
fn bob_publishing_meta_after_invite_moves_him_to_members() {
    let alice: Pubkey = [1u8; 32];
    let bob: Pubkey = [2u8; 32];
    let mut v = ChannelView::empty_named([7u8; 32]);
    fold(
        &mut v,
        [
            ev(
                alice,
                TYPE_CREATE,
                &ChannelCreate {
                    name: "c".to_string(),
                    description: None,
                    created_at: 1,
                },
            ),
            ev(
                alice,
                TYPE_MEMBER_META,
                &ChannelMemberMeta {
                    kind: MemberKind::Agent,
                    display_name: "alice".to_string(),
                    description: None,
                    asserted_at: 2,
                },
            ),
            ev(
                alice,
                TYPE_INVITE,
                &ChannelInvite {
                    agent: bob,
                    invited_at: 3,
                },
            ),
            ev(
                bob,
                TYPE_MEMBER_META,
                &ChannelMemberMeta {
                    kind: MemberKind::Agent,
                    display_name: "bob".to_string(),
                    description: None,
                    asserted_at: 4,
                },
            ),
        ],
    );
    assert!(!v.pending.contains(&bob));
    assert!(v.members.contains_key(&bob));
}

#[test]
fn invite_on_dm_topic_rejected() {
    let alice: Pubkey = [1u8; 32];
    let bob: Pubkey = [2u8; 32];
    let carol: Pubkey = [3u8; 32];
    let mut v = ChannelView::empty_dm([7u8; 32], vec![alice, bob]);
    fold(
        &mut v,
        [
            ev(
                alice,
                TYPE_MEMBER_META,
                &ChannelMemberMeta {
                    kind: MemberKind::Agent,
                    display_name: "alice".to_string(),
                    description: None,
                    asserted_at: 1,
                },
            ),
            ev(
                alice,
                TYPE_INVITE,
                &ChannelInvite {
                    agent: carol,
                    invited_at: 2,
                },
            ),
        ],
    );
    assert!(v.pending.is_empty(), "DM topics reject invites");
}

#[test]
fn duplicate_invite_is_noop() {
    let alice: Pubkey = [1u8; 32];
    let bob: Pubkey = [2u8; 32];
    let mut v = ChannelView::empty_named([7u8; 32]);
    fold(
        &mut v,
        [
            ev(
                alice,
                TYPE_CREATE,
                &ChannelCreate {
                    name: "c".to_string(),
                    description: None,
                    created_at: 1,
                },
            ),
            ev(
                alice,
                TYPE_MEMBER_META,
                &ChannelMemberMeta {
                    kind: MemberKind::Agent,
                    display_name: "alice".to_string(),
                    description: None,
                    asserted_at: 2,
                },
            ),
            ev(
                alice,
                TYPE_INVITE,
                &ChannelInvite {
                    agent: bob,
                    invited_at: 3,
                },
            ),
            ev(
                alice,
                TYPE_INVITE,
                &ChannelInvite {
                    agent: bob,
                    invited_at: 5,
                },
            ),
        ],
    );
    assert_eq!(v.pending.len(), 1);
}
```

- [ ] **Step 2: Run tests to confirm RED**

Run: `cargo test -p wires-core channel::replay`
Expected: invite-related tests fail.

- [ ] **Step 3: Implement rule 6**

Update the `apply` match arm:

```rust
fn apply(view: &mut ChannelView, ev: &Event) {
    let is_meta = ev.content_type == TYPE_MEMBER_META;
    if !is_meta && !publisher_has_meta(view, &ev.sender) && ev.content_type != TYPE_CREATE {
        return;
    }
    match ev.content_type.as_str() {
        TYPE_CREATE => apply_create(view, ev),
        TYPE_INVITE => apply_invite(view, ev),
        TYPE_MEMBER_META => apply_member_meta(view, ev),
        _ => {}
    }
}

fn apply_invite(view: &mut ChannelView, ev: &Event) {
    // Rule 2: DM topics reject invites.
    if matches!(view.variant, ChannelVariant::Dm { .. }) {
        return;
    }
    // Rule 6: publisher must be a full member. publisher_has_meta already
    // verified by the gate in `apply`, but invite is only meaningful if the
    // sender is in members (not just on-log).
    if !view.members.contains_key(&ev.sender) {
        return;
    }
    let parsed: ChannelInvite = match ev.data.as_ref().and_then(|d| serde_json::from_value(d.clone()).ok()) {
        Some(v) => v,
        None => return,
    };
    if view.members.contains_key(&parsed.agent) || view.pending.contains(&parsed.agent) {
        return; // already in roster; no-op
    }
    view.pending.insert(parsed.agent);
}
```

- [ ] **Step 4: Run tests to confirm GREEN**

Run: `cargo test -p wires-core channel::replay`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/wires-core/src/channel/replay.rs
git commit -m "$(cat <<'EOF'
core(channel): fold rule 6 — __channel.invite + pending tracking

Invitees enter `pending`; promoted to `members` when they publish their own
member_meta. DM topics reject invites. Duplicates are no-ops.

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

---

## Task 12: `wires-node::channel` — open a `ChannelView` from disk

**Files:**
- Create: `crates/wires-node/src/channel.rs`
- Modify: `crates/wires-node/src/lib.rs`
- Modify: `crates/wires-node/src/error.rs` (one new variant)

- [ ] **Step 1: Add the error variant**

Append to `crates/wires-node/src/error.rs` (inside the existing `NodeError` enum and `Result<T>` alias module — match the snafu pattern):

```rust
    #[snafu(display("decrypt channel envelope failed on topic {topic_id_hex}, at {location}"))]
    ChannelDecrypt {
        topic_id_hex: String,
        #[snafu(implicit)]
        location: snafu::Location,
        source: wires_crypto::CryptoError,
    },
```

(If your existing error file uses a different snafu pattern — e.g., a single big `#[derive(Snafu)] pub enum NodeError`, match its style precisely.)

- [ ] **Step 2: Write the failing test**

Create `crates/wires-node/src/channel.rs`:

```rust
//! Replay a topic log into a `wires_core::channel::ChannelView`. Spec §4.
//!
//! This is the I/O boundary: read ciphertext entries from the on-disk
//! `TopicLog`, decrypt with the relevant epoch key, decode `CanonicalContent`,
//! and drive `wires_core::channel::fold`.

use snafu::ResultExt;
use wires_core::channel::{Event, fold, ChannelVariant, ChannelView};
use wires_core::wire::{Pubkey, TopicId, WireMessage};
use wires_core::CanonicalContent;
use wires_crypto::decrypt_standard;
use wires_store::{EpochKey, TopicLog};

use crate::error::{ChannelDecryptSnafu, CoreSnafu, Result, StoreSnafu};

/// Replay all decrypted, well-formed entries of `log` into `view`. Public
/// entries (`MessageKind::Public`) carry the canonical content as-is in
/// `ciphertext`; standard-encrypted entries are decrypted with `epoch_key`.
/// Sealed-to entries are skipped — none of the three channel reserved types
/// uses `SealedTo`, so any sealed entry in a channel log is by convention a
/// `__topic.history_grant` from the substrate layer and is not consumed here.
pub fn replay_into(
    view: &mut ChannelView,
    log: &TopicLog,
    epoch_key: &EpochKey,
) -> Result<()> {
    use wires_core::wire::MessageKind;
    let entries = log.iter_all().context(StoreSnafu)?;
    let mut events: Vec<Event> = Vec::new();
    for entry in entries {
        let msg = entry.message;
        let content = match msg.kind {
            MessageKind::Public => {
                CanonicalContent::from_canonical_bytes(&msg.ciphertext).context(CoreSnafu)?
            }
            MessageKind::Standard => {
                // AAD is the envelope with ciphertext/payload_len/signature zeroed.
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

fn aad_for(msg: &WireMessage) -> wires_core::Result<Vec<u8>> {
    let mut aad_msg = msg.clone();
    aad_msg.signature = [0u8; 64];
    aad_msg.payload_len = 0;
    aad_msg.ciphertext.clear();
    aad_msg.signing_bytes()
}

/// Detect a DM topic_id against a known set of (root, candidate-other-pubkey)
/// pairs. Returns the sorted participant list on a match, or `None` if `topic_id`
/// is not a DM in this household.
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

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use rand_core::OsRng;
    use tempfile::TempDir;
    use wires_core::channel::schemas::{ChannelCreate, ChannelMemberMeta};
    use wires_core::channel::types::MemberKind;
    use wires_core::CanonicalContent;
    use wires_core::wire::MessageKind;

    fn open_log(dir: &std::path::Path, topic_id: [u8; 32]) -> TopicLog {
        TopicLog::open(&dir.join(format!("log_{}.redb", hex::encode(topic_id)))).unwrap()
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
```

Add to `crates/wires-node/src/lib.rs`:

```rust
pub mod channel;
```

- [ ] **Step 3: Run tests**

Run: `cargo test -p wires-node channel::`
Expected: PASS.

- [ ] **Step 4: Commit**

```bash
git add crates/wires-node/
git commit -m "$(cat <<'EOF'
node(channel): replay a TopicLog into wires_core::channel::ChannelView

I/O boundary: decrypts public/standard entries with the topic epoch key
and drives the pure fold. detect_dm helper bounded to 2-party per spec §15.

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

---

## Task 13: `cmd::pair_approve` always grants `channels.**`

**Files:**
- Modify: `crates/wires-cli/src/cmd/pair_approve.rs`

- [ ] **Step 1: Add a test asserting the cap has `channels.**`**

Append a unit test at the bottom of `crates/wires-cli/src/cmd/pair_approve.rs` (after the existing helpers). Note: pair_approve does significant I/O — we test the cap-building logic by extracting it into a small helper.

Refactor: extract the per-scope loop into a pure function:

```rust
pub(super) fn build_cap_globs(requested: &[wires_net::pair::RequestedScope]) -> (Vec<String>, Vec<Right>) {
    let mut topics: Vec<String> = Vec::new();
    let mut rights: Vec<Right> = Vec::new();
    let mut seen_rights = std::collections::HashSet::new();
    for scope in requested {
        topics.push(scope.topic_name.clone());
        for r in &scope.rights {
            if seen_rights.insert(*r) {
                rights.push(*r);
            }
        }
    }
    // Channels broad glob — every paired agent participates in the channel layer.
    if !topics.iter().any(|t| t == "channels.**") {
        topics.push("channels.**".to_string());
    }
    if !rights.contains(&Right::Read) {
        rights.push(Right::Read);
    }
    if !rights.contains(&Right::Write) {
        rights.push(Right::Write);
    }
    (topics, rights)
}

#[cfg(test)]
mod tests {
    use super::*;
    use wires_net::pair::RequestedScope;

    #[test]
    fn build_cap_globs_always_adds_channels_glob() {
        let scopes = vec![RequestedScope {
            topic_name: "home.notes".to_string(),
            rights: vec![Right::Read],
        }];
        let (topics, rights) = build_cap_globs(&scopes);
        assert!(topics.contains(&"channels.**".to_string()));
        assert!(rights.contains(&Right::Read));
        assert!(rights.contains(&Right::Write));
    }

    #[test]
    fn build_cap_globs_no_duplicate_channels_glob() {
        let scopes = vec![RequestedScope {
            topic_name: "channels.**".to_string(),
            rights: vec![Right::Read, Right::Write],
        }];
        let (topics, _rights) = build_cap_globs(&scopes);
        assert_eq!(topics.iter().filter(|t| *t == "channels.**").count(), 1);
    }
}
```

- [ ] **Step 2: Wire the helper into the main `run` flow**

Inside `pub async fn run(...)`, replace the existing loop that builds `cap_topics` / `cap_rights` with a call to `build_cap_globs(&scopes)`. Keep the loop for `topic_keys` / `topic_names` (those still need per-scope expansion). Concretely, the body that previously had:

```rust
let mut cap_topics: Vec<String> = Vec::new();
let mut cap_rights: Vec<Right> = Vec::new();
let mut seen_rights = std::collections::HashSet::new();
for scope in &scopes {
    let topic_id = name_map
        .get(&scope.topic_name)
        .ok_or_else(|| invalid!("unknown topic '{}'", scope.topic_name))?;
    /* … */
    cap_topics.push(scope.topic_name.clone());
    for r in &scope.rights {
        if seen_rights.insert(*r) {
            cap_rights.push(*r);
        }
    }
}
```

becomes:

```rust
for scope in &scopes {
    let topic_id = name_map
        .get(&scope.topic_name)
        .ok_or_else(|| invalid!("unknown topic '{}'", scope.topic_name))?;
    /* … existing topic_keys / topic_names push lines stay … */
}
let (cap_topics, cap_rights) = build_cap_globs(&scopes);
```

- [ ] **Step 3: Run tests**

Run: `cargo test -p wires-cli pair_approve`
Expected: PASS, including the two new unit tests.

Run: `cargo build --workspace` — make sure nothing else broke.

- [ ] **Step 4: Commit**

```bash
git add crates/wires-cli/src/cmd/pair_approve.rs
git commit -m "$(cat <<'EOF'
cli(pair-approve): always grant channels.** in the cap

Every paired agent gets channels.** (Read+Write) by default so they can
participate in the channel layer. Operator narrows by editing the cap
after approval if desired.

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

---

## Task 14: `publish_helpers::resolve_cap_for_topic`

**Files:**
- Modify: `crates/wires-cli/src/cmd/publish_helpers.rs`

- [ ] **Step 1: Add the helper + test**

Append to `crates/wires-cli/src/cmd/publish_helpers.rs`:

```rust
/// Return the first non-revoked cap held by the local node that covers
/// `topic_name` for `Right::Write`. Returns `None` if no such cap exists.
pub fn find_write_cap_for(node: &wires_node::Node, topic_name: &str) -> Option<wires_core::CapId> {
    let caps = node.caps.all().ok()?;
    for (cap_id, entry) in caps {
        if entry.revoked {
            continue;
        }
        if entry.cap.allows(topic_name, wires_core::Right::Write).is_ok() {
            return Some(cap_id);
        }
    }
    None
}
```

(If a unit test for this helper is feasible — e.g., construct a `Node` against a `TempDir` and seed a cap directly into `caps` — add one. Otherwise the integration tests in Task 27 exercise it end-to-end.)

- [ ] **Step 2: Confirm workspace builds**

Run: `cargo build --workspace`

- [ ] **Step 3: Commit**

```bash
git add crates/wires-cli/src/cmd/publish_helpers.rs
git commit -m "$(cat <<'EOF'
cli(publish-helpers): add find_write_cap_for(topic_name)

Helper for channel/dm commands: auto-resolve which cap to put in the
envelope without making the user pass --cap on every channel publish.

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

---

## Task 15: `wires channel create`

**Files:**
- Create: `crates/wires-cli/src/cmd/channel.rs`
- Modify: `crates/wires-cli/src/cmd/mod.rs`
- Modify: `crates/wires-cli/src/main.rs`

- [ ] **Step 1: Implement the command**

Create `crates/wires-cli/src/cmd/channel.rs`:

```rust
//! wires channel ... subcommands. Spec §10.

use std::path::Path;

use rand_core::{OsRng, RngCore};
use snafu::ResultExt;
use wires_core::channel::schemas::{ChannelCreate, ChannelMemberMeta, TYPE_CREATE, TYPE_MEMBER_META};
use wires_core::channel::types::MemberKind;
use wires_core::wire::MessageKind;
use wires_core::{CanonicalContent, Capability};
use wires_core::cap::Right;
use wires_net::unix_now_ms;
use wires_node::{Node, NodeConfig, load_root_signing_key, upsert_topic_names};

use crate::cmd::publish_helpers::find_write_cap_for;
use crate::error::{CoreSnafu, IoSnafu, NodeSnafu, Result, StoreSnafu, TomlParseSnafu};
use crate::invalid;

pub async fn create(
    data_dir: &Path,
    name: &str,
    description: Option<&str>,
) -> Result<()> {
    let topic_name = if name.starts_with("channels.") {
        name.to_string()
    } else {
        format!("channels.{name}")
    };

    let raw = std::fs::read_to_string(data_dir.join("config.toml")).context(IoSnafu)?;
    let cfg: NodeConfig = toml::from_str(&raw).context(TomlParseSnafu)?;
    let node = Node::open(cfg).context(NodeSnafu)?;

    // Generate random topic_id and epoch key (spec §4).
    let mut topic_id = [0u8; 32];
    OsRng.fill_bytes(&mut topic_id);
    let mut epoch_key = [0u8; 32];
    OsRng.fill_bytes(&mut epoch_key);
    node.install_epoch_key(topic_id, 0, epoch_key)
        .context(NodeSnafu)?;
    upsert_topic_names(data_dir, [(topic_name.clone(), topic_id)]).context(NodeSnafu)?;

    // Resolve our cap.
    let cap_id = find_write_cap_for(&node, &topic_name)
        .ok_or_else(|| invalid!("no cap covers '{topic_name}' for Write"))?;

    let now = unix_now_ms();

    // Publish __channel.create (Public).
    publish_public(
        &node,
        topic_id,
        cap_id,
        TYPE_CREATE,
        &format!("created channel {topic_name}"),
        &ChannelCreate {
            name: topic_name.clone(),
            description: description.map(str::to_string),
            created_at: now,
        },
        now,
    )?;

    // Publish creator's __channel.member_meta (Public).
    let display_name = load_display_name(data_dir).unwrap_or_else(|| "wires-cli".to_string());
    publish_public(
        &node,
        topic_id,
        cap_id,
        TYPE_MEMBER_META,
        &format!("member {display_name}"),
        &ChannelMemberMeta {
            kind: MemberKind::Cli,
            display_name: display_name.clone(),
            description: None,
            asserted_at: now,
        },
        now,
    )?;

    println!("Created channel '{topic_name}' with id {}", hex::encode(topic_id));
    Ok(())
}

/// `text` is the human-readable summary required by `CanonicalContent::text`
/// (must be non-empty). `content` is serialized to `serde_json::Value` and
/// stored in `CanonicalContent::data`. Reused by Tasks 17, 18, 20 — keep
/// this signature stable.
pub(super) fn publish_public<T: serde::Serialize>(
    node: &Node,
    topic_id: [u8; 32],
    cap_id: wires_core::CapId,
    content_type: &str,
    text: &str,
    content: &T,
    timestamp: i64,
) -> Result<()> {
    let value = serde_json::to_value(content).map_err(|e| invalid!("serialize content: {e}"))?;
    let canonical = CanonicalContent::new(content_type, text).with_data(value);
    let (seq, prev_hash) = node.next_seq_and_prev_hash(&topic_id).context(NodeSnafu)?;
    let params = wires_node::PublishParams {
        topic_id,
        sender_sk: &node.ed_sk,
        cap_id,
        kind: MessageKind::Public,
        content: canonical,
        epoch: 0,
        seq,
        prev_hash,
        timestamp,
        keying: wires_node::KeyingMaterial::Public,
    };
    let msg = wires_node::build_message(&params).context(NodeSnafu)?;
    node.append_local(&msg).context(StoreSnafu)?;
    Ok(())
}

fn load_display_name(data_dir: &Path) -> Option<String> {
    let p = data_dir.join("me.json");
    if !p.exists() {
        return None;
    }
    let raw = std::fs::read_to_string(&p).ok()?;
    let v: serde_json::Value = serde_json::from_str(&raw).ok()?;
    v.get("display_name").and_then(|x| x.as_str()).map(str::to_string)
}
```

Note: `next_seq_and_prev_hash`, `append_local`, `build_message`, `KeyingMaterial`, `PublishParams` may need re-exports from `wires-node`. Check the current `wires-node/src/lib.rs` re-exports; add any missing ones in the same commit.

Modify `crates/wires-cli/src/cmd/mod.rs`:

```rust
pub mod channel;
```

Modify `crates/wires-cli/src/main.rs` — add a new `Cmd::Channel` variant and a `ChannelCmd` enum:

```rust
#[derive(Subcommand)]
enum ChannelCmd {
    /// Create a named channel.
    Create {
        name: String,
        #[arg(long)]
        description: Option<String>,
    },
}
```

Add to the top-level `Cmd` enum:

```rust
    /// Channel management (spec: wires-channels-design)
    #[command(subcommand)]
    Channel(ChannelCmd),
```

Add to the `match cli.command` block:

```rust
        Cmd::Channel(ChannelCmd::Create { name, description }) => {
            cmd::channel::create(&data_dir, &name, description.as_deref()).await
        }
```

- [ ] **Step 2: Smoke-build and a manual run**

Run: `cargo build --workspace`
Expected: success.

Run (manual smoke test):

```bash
mkdir -p /tmp/channels-smoke
WIRES_DATA=/tmp/channels-smoke ./target/debug/wires --data-dir /tmp/channels-smoke init --new-root
# (above should already exist if you bootstrapped before; skip if so)
./target/debug/wires --data-dir /tmp/channels-smoke channel create coord --description "weekly grocery"
```

Expected: command prints `Created channel 'channels.coord' with id ...`.

Inspect: `cat /tmp/channels-smoke/topic_names.json` should now include `channels.coord → <id-hex>`.

- [ ] **Step 3: Commit**

```bash
git add crates/wires-cli/ crates/wires-node/src/lib.rs
git commit -m "$(cat <<'EOF'
cli(channel): wires channel create <name> [--description]

Picks random topic_id + epoch key, publishes __channel.create plus the
creator's own __channel.member_meta. Auto-resolves the publishing cap
under the broad channels.** glob.

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

---

## Task 16: `wires channel list` + `wires channel members`

**Files:**
- Modify: `crates/wires-cli/src/cmd/channel.rs`
- Modify: `crates/wires-cli/src/main.rs`

- [ ] **Step 1: Add the commands**

Append to `crates/wires-cli/src/cmd/channel.rs`:

```rust
pub async fn list(data_dir: &Path) -> Result<()> {
    let raw = std::fs::read_to_string(data_dir.join("config.toml")).context(IoSnafu)?;
    let cfg: NodeConfig = toml::from_str(&raw).context(TomlParseSnafu)?;
    let node = Node::open(cfg).context(NodeSnafu)?;
    let names = wires_node::load_topic_names(data_dir).context(IoSnafu)?;
    let self_pk = node.ed_sk.verifying_key().to_bytes();

    let mut shown = 0;
    for (name, topic_id) in &names {
        if !name.starts_with("channels.") || name.starts_with("channels.dm.") {
            continue;
        }
        // Open the log + epoch key and replay to check membership.
        let log = node.open_topic_log(topic_id).context(NodeSnafu)?;
        let (_epoch, key) = match node.epoch_keys_for(topic_id).context(NodeSnafu)?.latest() {
            Ok(Some(x)) => x,
            _ => continue,
        };
        let view = wires_node::channel::open_named(*topic_id, &log, &key).context(NodeSnafu)?;
        if view.members.contains_key(&self_pk) {
            if let wires_core::channel::ChannelVariant::Named { name: n, .. } = &view.variant {
                println!("{}  {}  members={}  pending={}", n, hex::encode(topic_id), view.members.len(), view.pending.len());
            }
            shown += 1;
        }
    }
    if shown == 0 {
        println!("(no channels)");
    }
    Ok(())
}

pub async fn members(data_dir: &Path, name: &str) -> Result<()> {
    let topic_name = if name.starts_with("channels.") {
        name.to_string()
    } else {
        format!("channels.{name}")
    };
    let raw = std::fs::read_to_string(data_dir.join("config.toml")).context(IoSnafu)?;
    let cfg: NodeConfig = toml::from_str(&raw).context(TomlParseSnafu)?;
    let node = Node::open(cfg).context(NodeSnafu)?;
    let topic_id = wires_node::resolve_topic(data_dir, &topic_name).context(IoSnafu)?;
    let log = node.open_topic_log(&topic_id).context(NodeSnafu)?;
    let (_epoch, key) = node.epoch_keys_for(&topic_id).context(NodeSnafu)?
        .latest().context(StoreSnafu)?
        .ok_or_else(|| invalid!("no epoch key for {topic_name}"))?;
    let view = wires_node::channel::open_named(topic_id, &log, &key).context(NodeSnafu)?;
    for (pk, meta) in &view.members {
        println!("{}  {:?}  {}  {}", hex::encode(pk), meta.kind, meta.display_name, meta.description.as_deref().unwrap_or(""));
    }
    if !view.pending.is_empty() {
        println!("--- pending ---");
        for pk in &view.pending {
            println!("{}  (no meta yet)", hex::encode(pk));
        }
    }
    Ok(())
}
```

Add CLI variants:

```rust
    List,
    Members { name: String },
```

Wire up dispatch in `main.rs`.

- [ ] **Step 2: Smoke test**

```bash
./target/debug/wires --data-dir /tmp/channels-smoke channel list
./target/debug/wires --data-dir /tmp/channels-smoke channel members coord
```

Both should produce sensible output (one channel listed; one member — yourself).

- [ ] **Step 3: Commit**

```bash
git add crates/wires-cli/
git commit -m "$(cat <<'EOF'
cli(channel): wires channel list + wires channel members

List replays every channels.* topic the agent has on disk; channel members
opens a specific channel and prints the roster.

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

---

## Task 17: `wires channel invite`

**Files:**
- Modify: `crates/wires-cli/src/cmd/channel.rs`
- Modify: `crates/wires-cli/src/main.rs`

- [ ] **Step 1: Implement**

Append to `crates/wires-cli/src/cmd/channel.rs`:

```rust
use wires_core::channel::schemas::{ChannelInvite, TYPE_INVITE};

pub async fn invite(data_dir: &Path, name: &str, agent_pubkey_hex: &str) -> Result<()> {
    let topic_name = if name.starts_with("channels.") {
        name.to_string()
    } else {
        format!("channels.{name}")
    };
    let agent: [u8; 32] = hex::decode(agent_pubkey_hex)
        .map_err(|e| invalid!("agent pubkey not hex: {e}"))?
        .try_into()
        .map_err(|_| invalid!("agent pubkey must be 32 bytes"))?;

    let raw = std::fs::read_to_string(data_dir.join("config.toml")).context(IoSnafu)?;
    let cfg: NodeConfig = toml::from_str(&raw).context(TomlParseSnafu)?;
    let node = Node::open(cfg).context(NodeSnafu)?;
    let topic_id = wires_node::resolve_topic(data_dir, &topic_name).context(IoSnafu)?;
    let cap_id = find_write_cap_for(&node, &topic_name)
        .ok_or_else(|| invalid!("no cap covers '{topic_name}'"))?;
    let (_epoch, key) = node.epoch_keys_for(&topic_id).context(NodeSnafu)?
        .latest().context(StoreSnafu)?
        .ok_or_else(|| invalid!("no epoch key for {topic_name}"))?;
    let now = unix_now_ms();

    // Publish FIRST: sealed __topic.history_grant (so a partial-failure
    // leaves the invitee with a usable key but no invite event — harmless;
    // the next attempt re-publishes both).
    let canonical = CanonicalContent::new(
        "__topic.history_grant",
        "epoch key for new member",
    )
    .with_data(serde_json::json!({
        "epoch": 0,
        "key_hex": hex::encode(key),
    }));
    let (seq, prev_hash) = node.next_seq_and_prev_hash(&topic_id).context(NodeSnafu)?;
    let params = wires_node::PublishParams {
        topic_id,
        sender_sk: &node.ed_sk,
        cap_id,
        kind: MessageKind::SealedTo(agent),
        content: canonical,
        epoch: 0,
        seq,
        prev_hash,
        timestamp: now,
        keying: wires_node::KeyingMaterial::SealedRecipient(&agent),
    };
    let grant_msg = wires_node::build_message(&params).context(NodeSnafu)?;
    node.append_local(&grant_msg).context(StoreSnafu)?;

    // Then: public __channel.invite.
    publish_public(
        &node,
        topic_id,
        cap_id,
        TYPE_INVITE,
        &format!("invited {agent_pubkey_hex}"),
        &ChannelInvite {
            agent,
            invited_at: now,
        },
        now,
    )?;

    println!("Invited {} to {topic_name}", agent_pubkey_hex);
    Ok(())
}
```

Add CLI variant `Invite { name: String, agent: String }` and dispatch.

- [ ] **Step 2: Confirm build**

Run: `cargo build --workspace`

- [ ] **Step 3: Commit**

```bash
git add crates/wires-cli/
git commit -m "$(cat <<'EOF'
cli(channel): wires channel invite <name> <agent_pubkey>

Publishes sealed __topic.history_grant (carrying the epoch key) followed
by public __channel.invite. Order matters — see spec §8 Invite flow.

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

---

## Task 18: `wires dm <pubkey>` (open-and-interactive)

**Files:**
- Create: `crates/wires-cli/src/cmd/dm.rs`
- Modify: `crates/wires-cli/src/cmd/mod.rs`
- Modify: `crates/wires-cli/src/main.rs`

- [ ] **Step 1: Implement**

Create `crates/wires-cli/src/cmd/dm.rs`:

```rust
//! wires dm ... subcommands. Spec §10.

use std::path::Path;

use snafu::ResultExt;
use wires_core::channel::derive::{dm_epoch_key, dm_topic_id, dm_topic_name, sort_participants};
use wires_core::channel::schemas::{ChannelMemberMeta, TYPE_MEMBER_META};
use wires_core::channel::types::MemberKind;
use wires_core::wire::MessageKind;
use wires_core::CanonicalContent;
use wires_net::unix_now_ms;
use wires_node::{Node, NodeConfig, load_root_signing_key, upsert_topic_names};

use crate::cmd::publish_helpers::find_write_cap_for;
use crate::error::{IoSnafu, NodeSnafu, Result, StoreSnafu, TomlParseSnafu};
use crate::invalid;

pub async fn open(data_dir: &Path, other_pubkey_hex: &str, message: Option<&str>) -> Result<()> {
    let other: [u8; 32] = hex::decode(other_pubkey_hex)
        .map_err(|e| invalid!("agent pubkey not hex: {e}"))?
        .try_into()
        .map_err(|_| invalid!("agent pubkey must be 32 bytes"))?;

    let raw = std::fs::read_to_string(data_dir.join("config.toml")).context(IoSnafu)?;
    let cfg: NodeConfig = toml::from_str(&raw).context(TomlParseSnafu)?;
    let cfg_root: [u8; 32] = hex::decode(&cfg.root_pubkey_hex)
        .map_err(|e| invalid!("root pubkey in config not hex: {e}"))?
        .try_into()
        .map_err(|_| invalid!("root pubkey must be 32 bytes"))?;
    let node = Node::open(cfg).context(NodeSnafu)?;
    let self_pk = node.ed_sk.verifying_key().to_bytes();

    // Derive topic_id + epoch key. No on-wire exchange (spec §5).
    let participants = sort_participants(vec![self_pk, other]);
    let topic_id = dm_topic_id(&cfg_root, &participants);
    // For the DH we need the OTHER side's x25519 pubkey. In v1 we look it up
    // from topic_names / pair-time data — for now require it to be present
    // in `pair_pending.json`'s known-roster cache or fall back to the
    // operator's identity.x25519 alongside identity.ed25519 in the data dir.
    // If the spec is implemented end-to-end, the pair grant will have
    // recorded the other agent's x25519 — that's the v1 path.
    let other_x_pk = lookup_x25519_pubkey(data_dir, &other)
        .ok_or_else(|| invalid!("no x25519 pubkey on file for {other_pubkey_hex} — pair with them first"))?;
    let epoch_key = dm_epoch_key(&node.x_sk.to_bytes(), &other_x_pk, &cfg_root, &participants);

    // Install epoch key locally, register the topic name.
    node.install_epoch_key(topic_id, 0, epoch_key).context(NodeSnafu)?;
    let topic_name = dm_topic_name(&topic_id);
    upsert_topic_names(data_dir, [(topic_name.clone(), topic_id)]).context(NodeSnafu)?;

    let cap_id = find_write_cap_for(&node, &topic_name)
        .ok_or_else(|| invalid!("no cap covers '{topic_name}'"))?;

    let now = unix_now_ms();

    // If we have no on-log member_meta yet, publish one.
    let log = node.open_topic_log(&topic_id).context(NodeSnafu)?;
    let view = wires_node::channel::open_dm(topic_id, participants.clone(), &log, &epoch_key)
        .context(NodeSnafu)?;
    if !view.members.contains_key(&self_pk) {
        let display_name = load_display_name(data_dir).unwrap_or_else(|| "wires-cli".to_string());
        publish_public_helper(
            &node,
            topic_id,
            cap_id,
            TYPE_MEMBER_META,
            &format!("member {display_name}"),
            &ChannelMemberMeta {
                kind: MemberKind::Cli,
                display_name: display_name.clone(),
                description: None,
                asserted_at: now,
            },
            now,
        )?;
    }

    if let Some(msg_text) = message {
        // Standard-encrypted note.
        let canonical = CanonicalContent::new("agent.note", msg_text);
        let (seq, prev_hash) = node.next_seq_and_prev_hash(&topic_id).context(NodeSnafu)?;
        let params = wires_node::PublishParams {
            topic_id,
            sender_sk: &node.ed_sk,
            cap_id,
            kind: MessageKind::Standard,
            content: canonical,
            epoch: 0,
            seq,
            prev_hash,
            timestamp: unix_now_ms(),
            keying: wires_node::KeyingMaterial::StandardEpochKey(&epoch_key),
        };
        let msg = wires_node::build_message(&params).context(NodeSnafu)?;
        node.append_local(&msg).context(StoreSnafu)?;
    }

    println!("DM topic {topic_name}");
    Ok(())
}

fn lookup_x25519_pubkey(data_dir: &Path, agent: &[u8; 32]) -> Option<[u8; 32]> {
    // v1: read an optional roster cache `dm_roster.json` mapping agent_ed25519_hex
    // -> agent_x25519_hex. This file is populated at pair-approve time.
    // If absent, return None — caller surfaces a helpful error.
    let p = data_dir.join("dm_roster.json");
    if !p.exists() {
        return None;
    }
    let raw = std::fs::read_to_string(&p).ok()?;
    let map: std::collections::HashMap<String, String> = serde_json::from_str(&raw).ok()?;
    let hex_key = map.get(&hex::encode(agent))?;
    let bytes = hex::decode(hex_key).ok()?;
    bytes.try_into().ok()
}

fn load_display_name(data_dir: &Path) -> Option<String> {
    let p = data_dir.join("me.json");
    if !p.exists() {
        return None;
    }
    let raw = std::fs::read_to_string(&p).ok()?;
    let v: serde_json::Value = serde_json::from_str(&raw).ok()?;
    v.get("display_name").and_then(|x| x.as_str()).map(str::to_string)
}

fn publish_public_helper<T: serde::Serialize>(
    node: &Node,
    topic_id: [u8; 32],
    cap_id: wires_core::CapId,
    content_type: &str,
    text: &str,
    content: &T,
    timestamp: i64,
) -> Result<()> {
    let value = serde_json::to_value(content).map_err(|e| invalid!("serialize content: {e}"))?;
    let canonical = CanonicalContent::new(content_type, text).with_data(value);
    let (seq, prev_hash) = node.next_seq_and_prev_hash(&topic_id).context(NodeSnafu)?;
    let params = wires_node::PublishParams {
        topic_id,
        sender_sk: &node.ed_sk,
        cap_id,
        kind: MessageKind::Public,
        content: canonical,
        epoch: 0,
        seq,
        prev_hash,
        timestamp,
        keying: wires_node::KeyingMaterial::Public,
    };
    let msg = wires_node::build_message(&params).context(NodeSnafu)?;
    node.append_local(&msg).context(StoreSnafu)?;
    Ok(())
}
```

Pair-approve change: at the end of `run` (after `install_grant` succeeds on the requester side, captured via the existing `OnInstalled` hook), append `(request.agent_pubkey_hex, request.agent_x25519_hex)` to `<data_dir>/dm_roster.json`. (Look up where the operator currently learns the requester's x25519 — `PairRequest` carries it; the field is in `wires-net/src/pair/request.rs:33`.) Add a small helper `upsert_dm_roster(data_dir, &[(ed_hex, x_hex)])` next to `upsert_topic_names` in `wires-node::topic_names`.

Add to `crates/wires-cli/src/cmd/mod.rs`:

```rust
pub mod dm;
```

CLI in `main.rs`:

```rust
#[derive(Subcommand)]
enum DmCmd {
    /// Open or send to a DM with another agent (by their ed25519 pubkey hex).
    Open {
        agent: String,
        #[arg(long)]
        message: Option<String>,
    },
    /// List local DM topics.
    List,
}
```

Add `Cmd::Dm(DmCmd)` and dispatch arms.

- [ ] **Step 2: Build**

Run: `cargo build --workspace`

- [ ] **Step 3: Commit**

```bash
git add crates/wires-cli/ crates/wires-node/src/topic_names.rs
git commit -m "$(cat <<'EOF'
cli(dm): wires dm open <agent> [--message ...]

Derives the DM topic_id and epoch key from sort(self, other, root). No
on-wire key exchange. Looks up the other agent's x25519 pubkey from
<data_dir>/dm_roster.json — pair_approve populates that file at grant
time.

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

---

## Task 19: `wires dm list`

**Files:**
- Modify: `crates/wires-cli/src/cmd/dm.rs`

- [ ] **Step 1: Add**

Append to `dm.rs`:

```rust
pub async fn list(data_dir: &Path) -> Result<()> {
    let names = wires_node::load_topic_names(data_dir).context(IoSnafu)?;
    let mut found = 0;
    for (name, topic_id) in names {
        if name.starts_with("channels.dm.") {
            println!("{name}  {}", hex::encode(topic_id));
            found += 1;
        }
    }
    if found == 0 {
        println!("(no DMs)");
    }
    Ok(())
}
```

Wire to CLI `DmCmd::List`.

- [ ] **Step 2: Commit**

```bash
git add crates/wires-cli/
git commit -m "$(cat <<'EOF'
cli(dm): wires dm list

Lists every channels.dm.* entry in topic_names.json.

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

---

## Task 20: `wires me set`

**Files:**
- Create: `crates/wires-cli/src/cmd/me.rs`
- Modify: `crates/wires-cli/src/cmd/mod.rs`
- Modify: `crates/wires-cli/src/main.rs`

- [ ] **Step 1: Implement**

Create `crates/wires-cli/src/cmd/me.rs`:

```rust
//! wires me set — update local member meta and republish into every joined
//! channels.* topic.

use std::path::Path;

use snafu::ResultExt;
use wires_core::channel::schemas::{ChannelMemberMeta, TYPE_MEMBER_META};
use wires_core::channel::types::MemberKind;
use wires_core::wire::MessageKind;
use wires_core::CanonicalContent;
use wires_net::unix_now_ms;
use wires_node::{Node, NodeConfig};

use crate::cmd::publish_helpers::find_write_cap_for;
use crate::error::{IoSnafu, NodeSnafu, Result, StoreSnafu, TomlParseSnafu};
use crate::invalid;

pub async fn set(
    data_dir: &Path,
    kind: &str,
    display_name: &str,
    description: Option<&str>,
) -> Result<()> {
    let parsed_kind: MemberKind = serde_json::from_str(&format!("\"{kind}\""))
        .map_err(|_| invalid!("kind must be one of: agent, api, cli, human, unknown"))?;

    // Persist to me.json so future `wires channel create` / `wires dm` pick it up.
    let me = serde_json::json!({
        "kind": kind,
        "display_name": display_name,
        "description": description,
    });
    std::fs::write(data_dir.join("me.json"), serde_json::to_vec_pretty(&me).unwrap())
        .context(IoSnafu)?;

    // Republish into every joined channels.* topic.
    let raw = std::fs::read_to_string(data_dir.join("config.toml")).context(IoSnafu)?;
    let cfg: NodeConfig = toml::from_str(&raw).context(TomlParseSnafu)?;
    let node = Node::open(cfg).context(NodeSnafu)?;
    let names = wires_node::load_topic_names(data_dir).context(IoSnafu)?;
    let now = unix_now_ms();
    let mut count = 0;
    for (name, topic_id) in names {
        if !name.starts_with("channels.") {
            continue;
        }
        let cap_id = match find_write_cap_for(&node, &name) {
            Some(id) => id,
            None => continue,
        };
        let meta = ChannelMemberMeta {
            kind: parsed_kind,
            display_name: display_name.to_string(),
            description: description.map(str::to_string),
            asserted_at: now,
        };
        let value = serde_json::to_value(&meta).unwrap();
        let canonical = CanonicalContent::new(TYPE_MEMBER_META, &format!("member {display_name}"))
            .with_data(value);
        let (seq, prev_hash) = node.next_seq_and_prev_hash(&topic_id).context(NodeSnafu)?;
        let params = wires_node::PublishParams {
            topic_id,
            sender_sk: &node.ed_sk,
            cap_id,
            kind: MessageKind::Public,
            content: canonical,
            epoch: 0,
            seq,
            prev_hash,
            timestamp: now,
            keying: wires_node::KeyingMaterial::Public,
        };
        let msg = wires_node::build_message(&params).context(NodeSnafu)?;
        node.append_local(&msg).context(StoreSnafu)?;
        count += 1;
    }
    println!("Updated member_meta and republished into {count} channel(s).");
    Ok(())
}
```

Add CLI:

```rust
    /// Update this agent's self-described member metadata (kind/display_name/description).
    Me {
        #[arg(long)]
        kind: String,
        #[arg(long = "display-name")]
        display_name: String,
        #[arg(long)]
        description: Option<String>,
    },
```

Dispatch:

```rust
        Cmd::Me { kind, display_name, description } => {
            cmd::me::set(&data_dir, &kind, &display_name, description.as_deref()).await
        }
```

`mod.rs`:

```rust
pub mod me;
```

- [ ] **Step 2: Commit**

```bash
git add crates/wires-cli/
git commit -m "$(cat <<'EOF'
cli(me): wires me set --kind --display-name [--description]

Persists me.json for future channel creates/DMs and republishes
__channel.member_meta into every channels.* topic the agent has on disk.

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

---

## Task 21: wires-mcp — `wires_list_channels`

**Files:**
- Modify: `crates/wires-mcp/src/mcp/tools.rs`

- [ ] **Step 1: Add descriptor**

In `list_descriptors()` (line 11) append to the tools array:

```json
{"name":"wires_list_channels","description":"List channels (named + DMs) this agent is in","inputSchema":{"type":"object","properties":{}}}
```

- [ ] **Step 2: Add handler**

Add at the file end (mirroring `list_topics`):

```rust
async fn list_channels(state: &ServiceState, claims: &Claims) -> Result<Value, JsonRpcError> {
    let runtime = state.supervisor.get_or_open(&claims.sub).await.map_err(|e| {
        JsonRpcError { code: -32000, message: format!("unknown_user: {e}") }
    })?;
    let names = wires_node::load_topic_names(&runtime.node.config.data_dir).unwrap_or_default();
    let self_pk = runtime.node.ed_sk.verifying_key().to_bytes();
    let mut channels = Vec::new();
    for (name, topic_id) in &names {
        if !name.starts_with("channels.") {
            continue;
        }
        let log = match runtime.node.open_topic_log(topic_id) {
            Ok(l) => l,
            Err(_) => continue,
        };
        let (_e, key) = match runtime.node.epoch_keys_for(topic_id).ok().and_then(|k| k.latest().ok().flatten()) {
            Some(x) => x,
            None => continue,
        };
        let is_dm = name.starts_with("channels.dm.");
        let view = if is_dm {
            // For listing, an empty Dm view is fine; participants aren't needed
            // for the response shape.
            match wires_node::channel::open_dm(*topic_id, vec![], &log, &key) {
                Ok(v) => v,
                Err(_) => continue,
            }
        } else {
            match wires_node::channel::open_named(*topic_id, &log, &key) {
                Ok(v) => v,
                Err(_) => continue,
            }
        };
        if view.members.contains_key(&self_pk) {
            channels.push(serde_json::json!({
                "topic_id": hex::encode(topic_id),
                "name": name,
                "kind": if is_dm { "dm" } else { "named" },
                "member_count": view.members.len(),
                "pending_count": view.pending.len(),
            }));
        }
    }
    Ok(serde_json::json!({"channels": channels}))
}
```

- [ ] **Step 3: Add dispatch in `call`**

In `pub async fn call(...)` (line 302), add a match arm before the fallthrough error:

```rust
"wires_list_channels" => {
    let v = list_channels(state, claims).await?;
    Ok(text_content(v))
}
```

(Match the existing pattern for `wires_list_topics`. If you see helper functions like `text_content`, use them.)

- [ ] **Step 4: Commit**

```bash
git add crates/wires-mcp/
git commit -m "$(cat <<'EOF'
mcp: add wires_list_channels tool

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

---

## Task 22: wires-mcp — `wires_create_channel`

**Files:**
- Modify: `crates/wires-mcp/src/mcp/tools.rs`

Mirror Task 21: add descriptor, handler that reuses the same logic as `wires_cli::cmd::channel::create` (but on the supervisor's `NodeRuntime` instead of opening a `Node` from `data_dir`), and dispatch arm. The handler input schema is `{"name": "string", "description?": "string"}`.

Implementation notes:
- The CLI implementation in Task 15 should be lifted into a shared helper in `wires-node::channel` (e.g. `pub async fn create_named(node: &Node, name: &str, description: Option<&str>) -> Result<TopicId>`) so both CLI and MCP call the same code path. Do that refactor as part of this task.

End with a commit `mcp: add wires_create_channel tool` co-authored as above.

---

## Task 23: wires-mcp — `wires_channel_members`

**Files:**
- Modify: `crates/wires-mcp/src/mcp/tools.rs`

Add descriptor + handler + dispatch. Input: `{"name": "string"}`. Output: `{"members": [{"pubkey", "kind", "display_name", "description"}], "pending": ["pubkey"]}`.

Commit `mcp: add wires_channel_members tool`.

---

## Task 24: wires-mcp — `wires_invite_to_channel`

**Files:**
- Modify: `crates/wires-mcp/src/mcp/tools.rs`

Add descriptor + handler + dispatch. Input: `{"name": "string", "agent_pubkey": "hex"}`. Handler delegates to a shared helper `wires_node::channel::invite(...)`. Commit `mcp: add wires_invite_to_channel tool`.

---

## Task 25: wires-mcp — `wires_dm_open`

**Files:**
- Modify: `crates/wires-mcp/src/mcp/tools.rs`

Add descriptor + handler + dispatch. Input: `{"agent_pubkey": "hex"}`. Handler derives topic_id + epoch key, installs locally, returns `{"topic_id": "...", "name": "channels.dm.<hex>", "participants": ["hex", "hex"]}`. Commit `mcp: add wires_dm_open tool`.

---

## Task 26: wires-mcp — `wires_set_member_meta`

**Files:**
- Modify: `crates/wires-mcp/src/mcp/tools.rs`

Add descriptor + handler + dispatch. Input: `{"kind", "display_name", "description?"}`. Handler mirrors `wires_cli::cmd::me::set` against the supervisor's `NodeRuntime`. Commit `mcp: add wires_set_member_meta tool`.

---

## Task 27: Integration test — named channel create + invite + roster

**Files:**
- Create: `crates/wires-cli/tests/channels_named_it.rs`

- [ ] **Step 1: Author the test**

Create `crates/wires-cli/tests/channels_named_it.rs`. The test bootstraps two data dirs, pairs them via the existing pair flow (call into `wires_cli::cmd::pair_*` programmatically), runs `channel create` from agent A, simulates an invite to B's pubkey, opens A's `ChannelView`, confirms B is in `pending`, then simulates B publishing their own member_meta, re-opens the view, and confirms B is in `members`.

Pattern to follow: `crates/wires-cli/tests/end_to_end_it.rs` (if it exists) or the inline integration tests in `crates/wires-node/src/pair.rs::tests`. Use `TempDir`, `tokio::test`, and the test helpers that already wire iroh endpoints in-memory.

The test must be `#[ignore]` only if it needs real iroh discovery. If we can keep it as a unit-shaped fold test that pre-stages a log on disk and replays it, prefer that — see `wires_node::channel::tests` as a model.

- [ ] **Step 2: Confirm RED, then PASS, then commit**

Run the test, confirm it fails (test exists, behavior not wired), then implement (most behavior is already in the CLI). Commit:

```
test(channels): named-channel create-invite-roster integration

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
```

---

## Task 28: Integration test — DM independent derivation

**Files:**
- Create: `crates/wires-cli/tests/channels_dm_it.rs`

Pattern: two agents under the same root, both compute `dm_topic_id` + `dm_epoch_key` independently, assert identical results. Then agent A publishes a Standard-encrypted message; agent B decrypts using its independently-derived key. Confirm no message of type `__topic.history_grant` appears on the topic log (DMs do not exchange keys).

Commit `test(channels): DM independent derivation + no key exchange`.

---

## Task 29: Acceptance scenario (`#[ignore]`-marked)

**Files:**
- Create: `crates/wires-cli/tests/channels_three_agent_it.rs`

A → creates `coord` → invites B → B publishes meta → B invites C → B+C continue while A is offline → A reconnects, host-replays the missed messages, opens the view, sees the full roster + messages.

This is the spec §13 acceptance scenario. Mark `#[ignore]` (use `#[ignore = "live iroh + replay; runs under --ignored"]`).

Commit `test(channels): three-agent named-channel acceptance scenario`.

---

## Self-review checklist

Once Tasks 1–29 are complete, run through:

- [ ] `cargo fmt --all`
- [ ] `cargo clippy --workspace -- -D warnings`
- [ ] `cargo test --workspace` (~154 existing tests + new) — all pass
- [ ] `cargo test --workspace -- --ignored` — acceptance scenario passes
- [ ] Spec §3 non-goals respected (no kick/leave/ban, no admin delegation, no group DMs > 2)
- [ ] Spec §7 rule 6: pending → members transition is symmetric across all entry points (CLI, MCP, replay)
- [ ] Spec §8 Invite flow order: history_grant first, then invite (Task 17)
- [ ] Spec §15: cap glob is `channels.**` only; no `dm.**` glob anywhere
- [ ] No new `wires-host` code (host is unchanged per spec §14)
- [ ] No new ALPNs (channels reuse the existing gossip + replay paths)
- [ ] All new error variants use the snafu pattern with `#[snafu(implicit)] location`
- [ ] All new wire-format additions to `WireMessage::SigningView` mirror — N/A here (no new envelope fields), but confirm the existing safety net `signing_bytes_covers_every_non_signature_field` still passes.

---

## Notes for the executor

- **wires-node API gaps.** Several of the tasks call methods on `Node` that may not yet exist as `pub`: `next_seq_and_prev_hash`, `append_local`, `open_topic_log`, `epoch_keys_for`. Confirm at start of Task 15; if any are missing, expose them in `wires-node/src/lib.rs` as part of the same commit — they're already used internally by `publish.rs`.
- **`dm_roster.json`.** Tasks 18 and 25 rely on a new file populated by pair_approve. Tasks 13's refactor is the easiest place to teach `pair_approve` to write it; if you elide it in Task 13, add it in Task 18 instead.
- **Refactor opportunity in Tasks 22–26.** The MCP handlers should share helpers with the CLI commands. Put the shared logic in `wires-node::channel` so neither layer reinvents it.
- **All work happens on `main` unless using-git-worktrees was invoked.** The executor should branch via `superpowers:using-git-worktrees` if/when that fits.
