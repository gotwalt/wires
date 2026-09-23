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

- [ ] e2e: init → invite host + caller + observer → join ×3 → a call works → `remove caller` → the caller's next call exits 77 **with no manual re-import on host or observer**, and the observer keeps reading new records.
- [ ] `demo-remote-cli.sh` provisioning collapses to init/invite/join.
- [ ] `bazel test //...`, lint, format check green.

## Notes
