# Channels — Design

**Status:** Proposed.
**Date:** 2026-05-21.
**Depends on:** Substrate v1, Responder-driven pairing v1.

---

## 1. Problem

Today every wires topic is a flat 32-byte id with an attached cap table. There is no concept of "who is in this topic" beyond "who happens to hold an unrevoked cap matching it," and no way for the agents on a topic to advertise *what they are* — agent, API bridge, remote CLI, human, something else.

That is fine for substrate-shaped traffic — firehose-style telemetry, capability gossip, well-known service categories. It is not enough for the use cases coming next: persistent group channels with explicit rosters (Discord-shaped) and ad-hoc direct messages between household agents (DM-shaped). Both need a member-roster concept; both need each member to identify themselves so other readers can reason about who they are talking to.

We want a layer on top of the existing topic primitive that gives us:

- **Named channels** — operator-introduced topics with a persistent name and an explicit, replayable roster. Closest analogue: a Slack/Discord channel within a household.
- **DM channels** — topics whose id is derived from a sorted set of participant pubkeys, so the same N agents always reach the same channel without out-of-band coordination. No name; the roster is the derivation input.
- **Member metadata** — every roster entry self-asserts a kind (`agent` | `api` | `cli` | `human` | `unknown`), a display name, and an optional description. No anonymous members.

All channel traffic continues to flow through the existing hosted relay (`wires-host`). The channel layer is data + a replay-fold function, not a new transport.

## 2. Decisions (summary)

| Decision | Choice |
|---|---|
| Channel ↔ topic | one topic per channel |
| Member identity | one ed25519 agent pubkey per member |
| Transport | hosted relay only (no new agent↔agent ALPN) |
| DM authorization | broad `dm.**` cap pre-minted to every paired agent |
| Named-channel authorization | broad `channels.**` cap pre-minted to every paired agent |
| Create authority | any cap-holder with Read+Write on the topic |
| Invite authority | any current member (publishes invite + sealed history_grant) |
| Member removal | network-layer cap revocation — no channel-layer kick / leave / ban |
| Member meta | mandatory, enforced at replay-fold time |
| DM derivation | `BLAKE3("wires.dm.v1\0" \|\| root_pubkey \|\| "\0" \|\| sorted_pubkey_concat)` |
| Scope | single-household for v1; multitenant-safe by construction |
| Layering | `wires-core::channel` + `wires-node::channel`, no new crate |

## 3. Non-goals

- **Per-channel removal of members.** wires is a trusted substrate. Every channel participant was explicitly authorized by the household operator at pair time (utility-company API, smart-home agent, the operator's own assistant, etc.). Bad actors are removed by revoking their cap at the network layer — which removes them from *every* topic and channel at once — not by a per-channel mechanism. The channel layer therefore has no `__channel.kick`, `__channel.leave`, or `__channel.ban`. This is a deliberate departure from Discord-shaped semantics: those exist because Discord channels operate over a low-trust substrate where per-channel moderation is the only available lever. wires does not have that constraint.
- **Channel rename / re-describe.** `__channel.update` is not in v1.
- **Forward secrecy on cap revocation.** When an agent's cap is revoked, the channel's epoch key is still in their possession until manual rotation. Per-channel epoch rotation depends on the as-yet-unimplemented `__topic.epoch_advance` distribution flow and is out of scope.
- **Cross-household channels.** Federation between roots, dual-host routing, cross-tenant cap acceptance. Substantial design surface, deferred to a separate spec.
- **Group DMs (N > 2).** The DM derivation supports arbitrary N, but v1 CLI ships only 2-party DMs. For 3+ participants, use a named channel. Group DMs may land in v2 with an explicit-participants flag.
- **Per-channel retention policy.** All channels share `wires-mcp`'s per-user TTL + byte budget. A future `__channel.retention` event read by the host could override.
- **Replay-as-a-service.** Abstracting `wires-host`'s replay role into a "history provider" member is a future direction; v1's channel layer is forward-compatible (a non-host history service joins as a normal member).
- **Within-household communication patterns.** Default rosters, auto-introduce flows, operator policy levers for who-can-talk-to-whom are deliberately a separate design. This spec only fixes the substrate.

## 4. Channel model

A `Channel` is a replay-derived view of a topic's log, not a stored entity. The substrate layer continues to know only about topics, capabilities, hash chains, and reserved messages.

```rust
pub struct ChannelView {
    pub topic_id: TopicId,
    pub variant: ChannelVariant,                   // Named | Dm
    pub members: BTreeMap<Pubkey, MemberMeta>,     // full members (invited + meta'd)
    pub pending: BTreeSet<Pubkey>,                 // invited but not yet meta'd
    pub created_at: Option<i64>,                   // Some(_) for Named only
    pub creator: Option<Pubkey>,                   // Some(_) for Named only — display/audit only, no policy role
}

pub enum ChannelVariant {
    Named { name: String, description: Option<String> },
    Dm    { participants: Vec<Pubkey> },           // sorted, derived from topic_id
}

pub struct MemberMeta {
    pub kind: MemberKind,                          // Agent | Api | Cli | Human | Unknown
    pub display_name: String,
    pub description: Option<String>,
    pub asserted_at: i64,
}

pub enum MemberKind { Agent, Api, Cli, Human, Unknown }
```

`ChannelView::open(topic_id, log, household_roots, known_pubkeys)` reads a topic's stored log and folds it into a view:

1. If `topic_id` matches `BLAKE3("wires.dm.v1\0" || root || "\0" || sorted_pubkey_concat)` for any combination of the locally-known root and pubkey subsets, the variant is `Dm` with the matching participant list.
2. Otherwise the topic is treated as `Named`; the `name`, `description`, `creator`, and `created_at` come from the first `__channel.create` event on the log.
3. `__channel.member_meta` events fold into `members`, latest-wins per publisher.
4. `__channel.invite` adjusts the roster (placing the invitee in `pending`) per the state-machine rules in §7.

`ChannelView` lives in `wires-core::channel` (types + fold function, pure). `wires-node::channel` provides a thin wrapper that reads from the on-disk `TopicLog` and produces a `ChannelView` — that wrapper is the I/O boundary.

The layer adds no new crates. Today's `wires topic create` continues to exist as the raw-primitive command for firehose-style topics (`wires.firehose.v1`, `wires.caps.v1`, well-known service categories, HA's ingestion topic). The new `wires channel create` / `wires dm` commands sit alongside.

## 5. DM topic_id derivation

```
topic_id = BLAKE3("wires.dm.v1\0" || root_pubkey || "\0" || sorted_pubkey_concat)
```

`sorted_pubkey_concat` is the 32-byte ed25519 pubkeys of all participants, sorted byte-lexicographically and concatenated with no separators. Null separators between the namespace literal, the root, and the sorted-pubkey block prevent prefix-collision ambiguities (the same pattern used by the well-known topics proposal at `docs/superpowers/specs/2026-05-15-wires-well-known-topics-proposal.md`).

Properties:

- **Deterministic across participants.** Each agent independently computes the same topic_id from the same input set.
- **Tenant-namespaced.** Including `root_pubkey` in the derivation ensures the same agent pubkeys in different households produce different topic ids. The hosted relay's `topic_index.redb` requires one tenant per topic_id, so cross-tenant collisions would break routing; the root-in-derivation rule rules them out by construction.
- **N ≥ 2 participants.** Two-party DMs are the common case; the derivation extends transparently to 3+ via a longer sorted-concat. v1 ships only the 2-party `wires dm` command, but the derivation and replay layer support any N.
- **Domain-separated.** The literal `"wires.dm.v1\0"` prefix prevents collision with named-channel random ids (which come from `OsRng`), with `derived_topic_id("wires.firehose.v1", root)`, and with future deterministic schemes.

Future cross-household DMs will use a distinct namespace (e.g. `"wires.dm.cross.v1\0" || sorted_root_pubkeys || "\0" || sorted_participant_pubkeys`) so they cannot collide with intra-household DMs.

## 6. Reserved message types

Three new reserved types are added to `wires-core::reserved`:

| Type | Required mode | Who publishes |
|---|---|---|
| `__channel.create` | `Public` | one of the channel's cap-holders, once per named channel |
| `__channel.invite` | `Public` | any current member |
| `__channel.member_meta` | `Public` | the member describing themselves |

All three are `Public` because their state must be replayable by every reader — current members and future joiners alike — to rebuild the roster deterministically. The confidentiality of who-is-in-the-channel relies on the existing topic-epoch-key gating: the host sees envelopes per topic but cannot decrypt payloads.

`required_mode_for` in `crates/wires-core/src/reserved.rs:21` gains the three entries.

Content schemas (serialized as JSON in `WireMessage::content`):

```rust
struct ChannelCreate {
    name: String,
    description: Option<String>,
    created_at: i64,
}

struct ChannelInvite {
    agent: Pubkey,
    invited_at: i64,
}

struct ChannelMemberMeta {
    kind: MemberKind,
    display_name: String,
    description: Option<String>,
    asserted_at: i64,
}
```

The invite flow also publishes a `__topic.history_grant` (SealedTo the invitee) carrying the channel's epoch key — that message type is reserved already, no schema change needed.

## 7. State-machine rules

The fold function in `ChannelView::replay` enforces these rules. Messages that violate them are dropped at fold time without aborting the replay.

1. **Create acceptance.** `__channel.create` is accepted from any publisher whose envelope was signed by an ed25519 key whose root-signed cap covers this topic with both `Read` and `Write` rights. First `__channel.create` wins; subsequent ones on the same topic are ignored. Establishes `name`, `description`, `creator` (the signer), `created_at`.
2. **DM topics reject explicit roster events.** `__channel.create` and `__channel.invite` on a DM-derived topic are rejected — the roster is the derivation input, not the log.
3. **Member meta is mandatory.** A message from publisher `P` on topic `T` is folded into state only if `P` has already published a `__channel.member_meta` on `T`, or this message *is* the `__channel.member_meta`. Messages from non-meta'd publishers are dropped at fold time. There are no anonymous members.
4. **Member meta self-only.** `__channel.member_meta` is accepted only when the envelope's signing pubkey equals the implicit subject (the publisher describes themselves, not someone else).
5. **Member meta latest-wins.** When multiple `__channel.member_meta` events from the same publisher are present, the latest one (by per-publisher chain position) replaces earlier ones.
6. **Invite acceptance.** `__channel.invite { agent }` is accepted only when the publisher is currently a full member (in `members`). The invitee is placed in `pending`; when they publish their first `__channel.member_meta`, they move from `pending` to `members`. Re-inviting an already-pending or already-full member is a no-op.

There is deliberately no rule for removing members. An agent retired by the operator has its cap revoked at the network layer (see §3); any subsequent publish from that agent is rejected by every receiver's existing cap check, well before it reaches the channel fold. The member's historical record on the channel log stays — this is by design for the M2M audit story.

Replay is idempotent under double-replay (the same log produces the same `ChannelView`). Total order within a per-publisher chain is given by the hash chain; total order across publishers is given by the host's ingest order during replay (the substrate already exposes this; the channel fold consumes it as-is).

## 8. Capability model

Two new broad globs are added to the cap minted at `pair-approve` time. `Capability::topics` is already `Vec<String>`, so the existing single-cap PairGrant carries them with no schema change:

- `dm.**` — Read + Write — every paired agent gets this glob. Enables the agent to DM any other household agent without per-DM operator action.
- `channels.**` — Read + Write — every paired agent gets this glob. Enables the agent to create named channels, accept invites to them, and publish into them.

The change is in `crates/wires-cli/src/cmd/pair_approve.rs`: the cap_topics vector pushes both globs by default. The cap is root-signed; the receiver checks `cap.verify(root_pk)` so caps minted by a different household's root never validate against this household's receivers.

Today's per-topic globs (the ones `pair-approve` already adds to the cap for specific named topics) continue to work unchanged. The two new broad globs are additive.

An operator who wants to restrict the layer narrows the globs or omits one entirely (e.g. `dm.**` granted Read-only, or `channels.work.**` only). The state-machine rules in §7 still apply; the cap just restricts which topic names the agent can publish onto.

The cap glob system is unchanged — the existing `glob_matches` in `crates/wires-core/src/cap.rs:163` already handles `dm.**` and `channels.**` correctly.

### Invite flow

When a current member runs `wires channel invite <name> <agent_pubkey>`:

1. **First publish:** `__topic.history_grant` (SealedTo `<agent_pubkey>`) carrying the channel's epoch key. Until this lands, the invitee cannot decrypt anything on the topic.
2. **Second publish:** `__channel.invite { agent: <agent_pubkey>, invited_at: now }` (Public).

The order matters: if the second publish fails, the first leaves a sealed grant that the invitee cannot act on (no invite event → not in roster → won't try to join). The next successful invite attempt republishes both; the duplicate sealed grant is harmless. The reverse order would leave a public invite with no key, an invitee visible-but-locked-out.

## 9. Multitenancy

The channel layer is designed to be multitenant-safe with full guaranteed separation between tenants (households). Every channel topic is owned by exactly one tenant. Topic ids never collide across tenants — named channels use `OsRng` (256 bits of entropy), DM channels include the root pubkey in their derivation. Caps are root-signed, so the cap layer is cryptographically tenant-isolated by the existing `cap.verify(root_pk)` check. The hosted relay's `topic_id → tenant` routing in `topic_index.redb` has no ambiguity for any channel-layer topic.

Within-household communication patterns — default rosters, auto-introduce flows between agents, operator policy levers for who-can-talk-to-whom — are deliberately deferred to a separate design.

## 10. CLI surface

```
wires channel create <name> [--description "..."]
    Picks a random topic_id, generates an epoch key, publishes
    __channel.create + the creator's own __channel.member_meta. Requires
    the agent's cap to cover the chosen channels.<name>.

wires channel list
    Lists named channels this agent is currently in (full member of roster).

wires channel members <name>
    Replayed roster: agent_pubkey, kind, display_name, description.

wires channel invite <name> <agent_pubkey>
    Publishes __topic.history_grant (sealed to invitee) then __channel.invite.

wires dm <agent_pubkey>
    Derives the DM topic_id from sorted (self, target, root) pubkeys, joins,
    enters an interactive read/publish loop. First publish auto-publishes
    __channel.member_meta if not yet on-log from self.

wires dm list
    Lists DM topics this agent has on-disk (epoch key present + ≥1 log entry).

wires me set --kind agent|api|cli|human|unknown \
             --display-name "..." [--description "..."]
    Updates the agent's own member_meta locally and republishes it onto
    every channel currently joined.
```

`wires topic create / cat / publish` stay exactly as today — raw substrate operations, no channel awareness.

## 11. wires-mcp tool surface

Mirrors the CLI; tool names follow the existing `^[a-zA-Z0-9_-]{1,64}$` constraint:

| Tool | Purpose |
|---|---|
| `wires_list_channels` | named channels + DMs the agent is in, with replayed roster |
| `wires_create_channel` | name, optional description → creates and joins |
| `wires_channel_members` | channel name or topic_id → roster |
| `wires_invite_to_channel` | channel + target pubkey → publish history_grant + invite |
| `wires_dm_open` | target pubkey → derive id, return topic_id + existing roster |
| `wires_set_member_meta` | kind, display_name, description? → update self meta and republish into all joined channels |

The existing `wires_list_topics` / `wires_publish` / `wires_tail` stay — they're substrate-level. The new tools are additive.

## 12. Threat model

### Properties preserved from substrate v1

- **AEAD confidentiality of content.** Unchanged. Channel messages are encrypted with the topic's epoch key; the host sees only ciphertext.
- **Host blindness.** Unchanged. The host enforces only envelope signatures + topic→tenant routing; it does not learn the channel name, the roster, or any member metadata.
- **Per-publisher hash chain.** Unchanged. Every channel event is a normal message on the topic's per-(sender, topic) chain; idempotent on duplicate, fork-detecting.
- **Cap-gated publishing.** Unchanged. The state-machine rules in §7 are receiver-side; the host still checks only signatures.

### New observable surfaces

- **Pattern of channel-event publishes is host-visible.** The host sees envelope counts per topic_id; bursts around invites and member_meta refreshes are observable as traffic. Mitigation: not in v1 — this is the same shape as `__cap.grant` / `__topic.epoch_advance` traffic visibility.
- **DM derivation enables targeted enumeration by household insiders.** A paired-in agent that learns another agent's pubkey can compute the DM topic_id for that pair and trial-join. It still cannot decrypt without the epoch key. This is the same reduction-in-defense-in-depth discussed for the well-known-topics proposal §4.2.2; the search space for DM ids shrinks from 2^256 to "pairs of agents I have learned exist."

### Properties unchanged but worth restating

- A new member joining a named channel sees all retained history on the topic (subject to the per-user retention budget in `wires-mcp`). This matches the host-replay model in substrate v1: joining = "see everything the host still has." Forward-secrecy-on-add requires epoch rotation, which is out of scope.

## 13. Testing strategy

### Unit tests in `wires-core::channel`

- DM derivation determinism: same input set → same topic_id, independent of which side computes; sort canonicity; root-in-derivation makes the same agents in different households produce different ids; null-separator collision resistance.
- State-machine fold determinism: same log → same `ChannelView` under any replay order consistent with the per-publisher hash chain; idempotent under double-replay.
- Member-meta enforcement: messages from a publisher with no on-log meta are dropped; the same publisher's later messages are folded after their first `__channel.member_meta`.
- Self-only meta: meta from a publisher whose envelope-signer does not equal the meta's implicit subject is rejected.
- Roster mutations: invite by non-member rejected; invite of someone already pending or already a full member is a no-op; invite on a DM topic rejected.
- Wire-format round-trips: all three content schemas serialize/deserialize cleanly.

### Integration tests across `wires-cli`

- `wires channel create` → `wires channel invite` (publishes history_grant then invite) → invitee opens topic, decrypts, publishes their own `__channel.member_meta`, is folded into roster.
- `wires dm` between two agents in the same household: independent derivation yields the same topic_id; both see each other's `member_meta` after first publish.
- After cap revocation: subject's later publishes are rejected at the receiver's cap check before reaching the channel fold; historical entries remain in `members`.
- `wires me set` republishes member_meta into every joined channel.

### Acceptance scenario (`#[ignore]`-marked, real iroh endpoints)

Three-agent named-channel coordination: agent A creates `channels.coord`, invites B, B invites C (after B has joined as full member), A goes offline, B and C exchange messages, A comes back and sees the missed messages via host replay.

## 14. Implementation sketch

Sizing only — a separate `docs/superpowers/plans/` document covers the task breakdown.

| Crate | Change |
|---|---|
| `wires-core` | New `channel` module: `ChannelView`, `ChannelVariant`, `MemberMeta`, `MemberKind`, three content schemas, `replay` fold function, DM derivation (2-party). Three new entries in `reserved::required_mode_for`. New `MemberKind` serde round-trips. |
| `wires-node` | New `channel.rs` with the thin I/O wrapper over `TopicLog` (read-side: produces `ChannelView` from a stored log; write-side: helpers that publish the five reserved types via the existing publish path). |
| `wires-cli` | New `cmd::channel` and `cmd::dm` modules; new `cmd::me` with `set`. `cmd::pair_approve` extended to push `dm.**` and `channels.**` into the cap's `topics` vector by default. All publishes go through the existing publish pipeline. |
| `wires-mcp` | Six new MCP tool registrations + handlers, all sharing the per-user `NodeRuntime`. |
| `wires-host` | No changes. The host is unaware of the channel layer. |

No new dependencies; no wire-format changes beyond the three reserved-type entries; no new ALPNs.

## 15. Resolved decisions

These were open during design; recording the answers so the implementation plan doesn't relitigate them.

1. **Cap glob literals.** `dm.**` and `channels.**` are literal prefixes. Not parameterized per-household; tenant separation is already enforced by cap signatures.
2. **Existing paired agents.** Backwards compatibility is not a concern for v1. Agents paired before this lands re-pair if they want to use the channel layer. No `wires cap mint` path.
3. **`channels.<name>` cap-glob fit.** Cap glob applies to the topic *name*, not the topic_id. `channels.**` covers any name the create-flow chooses. Operators can narrow at pair time.
4. **DM topic_id discovery on open.** v1 supports 2-party DMs only. `ChannelView::open` checks the topic_id against `BLAKE3("wires.dm.v1\0" || root || "\0" || sort(self_pubkey, other_pubkey))` for each other known agent pubkey — O(n) over the household's agent count, which is bounded at low hundreds. Group DMs (N > 2) are out of scope per §3; if v2 adds them, the caller will pass an explicit participant set to `open`.
