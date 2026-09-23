# 14 — `init` / `invite` / `join` / `remove`: onboarding in one step each

**Lane:** O · **Depends on:** 12 · **Files:** `wires/admin/*`, a `join` command under caller/host (shared), a `ChannelRecord` variant for key rotation if needed

## Why

Today joining takes `roster add` → `roster commit` → `member` → `import` with
four credential files, and **every removal forces every remaining member to
re-import** a new head and sealed key by hand. That's fine for tests and
unusable for a demo or a team.

## Design

- `wires init [--channel ops]`: create the root key and this machine's node key in one keystore, add self to the roster, commit. The admin is a member too.
- `wires id`: print this node's id (what a joiner sends the admin). `join` prints it too if no invite is given.
- `wires invite <node-id> [--name alice] [--ttl 30d]`: roster add + commit + membership, bundled into **one invite token** (base64 JSON: membership, inclusion proof, roster head, sealed fabric key, channel name, bootstrap ticket of the admin's or a host's node). Prints the token, plus `wires join <token>` for copy-paste. Names are local labels in the admin's roster file (for `remove alice`), not identity.
- `wires join <token>`: imports everything and records the channel and bootstrap peers, so `watch`, `call` and `serve` need no `--peer`.
- `wires remove <node-id|name>`: roster remove + commit, then **distributes the new head and each remaining member's sealed key over the channel** (e.g. `ChannelRecord::Rekey { head, sealed: [SealedFabricKey…] }`, published by the admin's node). Members' tail/serve loops adopt it automatically (verify the root signature and head monotonicity; open their own sealed key). Revocation of the removed member stays immediate, as today (hosts re-read the head per connection once it's adopted). Check it against `docs/phase2-topics.md` (confidentiality: the removed member can read the Rekey record, since it's encrypted under the old key, but can't open anyone's sealed key).
- Membership TTLs: default long for the demo (30d), and `invite --ttl` overrides. Note the renewal story as a follow-up; don't build it.

## Acceptance

- [x] e2e: init → invite host + caller + observer → join ×3 → a call works → `remove caller` → the caller's next call exits 77 **with no manual re-import on host or observer**, and the observer keeps reading new records.
- [x] `demo-remote-cli.sh` provisioning collapses to init/invite/join.
- [x] `bazel test //...`, lint, format check green.

## Notes

*2026-09-23, lane O (worker).*

**Commands.** `wires init [--channel ops] [--ttl 30d]` (root + node key, self
in roster, commit v1, credentials installed, `channel.json`); `wires id`
(prints the node id, creating `node.seed` on first use); `wires invite
<node-id> [--name l] [--ttl 30d] [--peer <ticket>]…` (stdout = the token
only, notes on stderr); `wires join [<token>]` (no token = print id);
`wires remove <name|id> [--ttl]`. `--ttl` takes `30d/12h/90m/45s/2w` or
seconds and sets both the membership and the head expiry. Names live in the
admin's `names.json` (0600). Admin commands are under the Admin heading;
`id`/`join` under Caller ("every role joins the same way"). `wires watch`'s
topic is now optional (defaults to `channel.json`); `TopicArgs.topic` stays a
`String` (empty = joined channel) so card 13's `audit_context_in` is
untouched.

**Invite token** (`library::Invite`, `library/membership/invite.rs`):
base64url-no-pad of canonical JSON
`{format:1, channel, membership, head, entry:{proof, key:SealedFabricKey}, peers:[TopicPeer]}`.
~2.3 KB. **Not a secret**: everything is public or sealed to the invitee's
key; it reveals the channel name and peer addresses. `Invite::verify` checks
one root throughout, addressed to this node, unexpired, and opens the key.
Trust on first use: the token introduces the root (card 18 is the real
answer). `peers` = the admin's peer book for the channel (from `--peer`
tickets and neighbors its one-shot publishes met).

**Rekey record** (`library/membership/rekey.rs`):
`ChannelRecord::Rekey { head, entries: [{ proof, key }] }`, one per commit
(chunked at 32 members; gossip max message raised 4 KiB → 64 KiB in
`channel/topics.rs`, which also helps audit records with big stdin heads).
*Security argument:* nothing in it is the publisher's word — the head is
root-signed, each proof must recompute that head's Merkle root, each sealed
key is root-signed (new `SealedFabricKey::verify`) and sealed to its proof's
member; so anyone (a removed member included) who publishes or replays one can
only advance a reader to a *newer root-signed* head via the same
`adopt_if_newer` CAS admission uses, and hand it a key the root sealed to it.
It is published under the *outgoing* key (so current members can open it and
their ingest floor accepts it): the removed member can read it and learns the
head, the survivors' ids and Merkle paths — never the new fabric key, which is
only in plaintext in survivors' keyrings (confidentiality is still immediate,
§2.4.1). Revocation stays immediate at every node holding the new head, and
that is now "received the Rekey" (~1 RTT) rather than "operator imported".

**Distribution order** (`admin/commit.rs`): resolve the admin node's
*pre-commit* channel context → sign/seal (fails before persisting) → bump
`roster.json` → publish (resident `wires watch` via IPC if running, else
one-shot) to members that already held the old key → only then install the
admin's own part. Adoption (`channel/rekey.rs`): own key → own proof → proof
directory → head (CAS, last). The resident loop adopts on every received
envelope whatever its ingest verdict (a node whose head advanced via
admission first floor-refuses to store the record but still adopts it) and on
everything a catch-up inserts.

**Proof directory — the piece the card didn't name but needed.** Each invite
is a commit, so *every* invite stales every member's proof, and callers are
not resident (they never see a Rekey). So each Rekey also leaves
`roster-directory.json` (every member's proof under the current head, 0600).
`transport::roster_gate`, topic admission (both directions) and the watchdog
use `check_roster_inclusion_via`: a stale presented proof is accepted if the
directory for *exactly* the enforced head lists that caller — as strong as
the caller presenting it (public, root-committed; caller is still the
iroh-authenticated key). Result: a caller joined at v3 calls a host at v4, and
the watchdog no longer evicts every survivor after a commit. And a one-shot
publish (`login`) whose key is behind its head runs one catch-up pass and
adopts the Rekey before sealing (the demo's agent does exactly this: invited
at v3, logs in at v4).

**Files outside the lane (minimal):** `host/transport.rs` `roster_gate`
(≈10 lines: directory lookup + `check_roster_inclusion_via`);
`channel/admission.rs` (three `_via` call sites + `load_directory`);
`channel/topics.rs` (gossip max); `channel/watch.rs` (two `observe` hooks);
`channel/publish.rs` (`publish_one_shot_on`, `Messages::Many`, stale-key
catch-up); `channel/context.rs` (default channel); `render.rs` (🔑 line).
`.scripts/demo-remote-cli.sh`: provisioning → init/id/invite/join, plus a
second setup block right after step 1 (agent/observer invites need the
workbench's ticket via `invite --peer`), `watch`/`login` lose `--peer`, and
step 7 is `wires remove agent` with an assertion that the workbench's and
observer's `roster-head.json` match the admin's (no import). Serve lines
untouched; `tools add --topic-ticket` left for card 15. Spec: new
`docs/phase2-topics.md` §2.5.

**Residuals / follow-ups.** Membership renewal: memberships and heads expire
at `--ttl` (30d) and nothing renews them — next card should add `wires
renew` or re-issue on commit. A member offline across a commit and never
re-admitted by a peer holding the directory needs `wires invite <id>` again
(re-invite re-commits and re-issues). The admin machine is a member, so it
holds fabric keys (the "blind root" posture of `roster commit` no longer
holds for the init/invite path; plumbing is unchanged). The first invite
carries no peers (the host is the first peer); the admin learns peers only
via `--peer`. Envelopes under a key version a reader lacks when they arrive
are stored but not re-printed once the key lands (pre-existing behavior).

**Numbers.** `wires_test` 333 (was 312), `library_test` 273 (was 253),
`library_doc_test` 48 (was 45); lint, `format.check` green;
`demo-remote-cli.sh --quiet` green, 14 s.

**Integrator review (2026-09-23).** The proof directory is sound: `check_roster_inclusion_via` runs the directory's proof through the same `check_roster_inclusion` against the root-signed head as a presented proof. **Known trade-off, recorded:** a Rekey record carries every survivor's id and proof under the old key, so a removed member learns the post-removal member list. That weakens committed-roster.md's "the head hides the member set" property for removed members. Acceptable for the demo; revisit together with card 18. The Rekey cap is 32 members per record (chunked), and gossip messages are now up to 64 KiB. The merge with card 13 needed `policy: AnyMember` in the onboarding e2e fixture.
