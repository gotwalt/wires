# 36d — Simpler policy integrity: signed document + signed entries, no Merkle tree

**Lane:** D2 · **Depends on:** 36b · **Status:** review (built 2026-09-24, branch `worker/36d-no-merkle`) · **Files:** `library/services/{head,item,entry,signed_policy,policy_update,view}.rs` (`parts.rs`, `merkle.rs` removed), `library/directory/frames.rs`, `library/examples/policy_sizes.rs`, `wires/directory/`, card 36, card 37, fabric.md, protocol.md

## Why (the human, 2026-09-24)

"Can you explain what the Merkle tree is providing for us? … It's a very sophisticated data
structure. Is there a simpler way?" And, agreeing to the change: "the proofs keep the system
honest, and that's concretely valuable. Just want to balance it with using the right tool for the
right problem."

The tree (card 36a) let a node verify a *subset* of the policy against one root signature, so a
host could hold only its slice and a caller only its view without trusting the directory, and so
a directory couldn't mix item versions. It cost about 1,600 lines (tree, proofs, multiproofs,
update-apply) and a proof format to keep correct.

Hosts don't need subsets: they are machines the admin placed, and holding the whole policy was
already accepted in the original card 29. Callers need subsets, but each entry can carry its own
root signature, as a badge does. With that, integrity needs no tree. The Merkle tree belongs in
[card 09](09-witness.md), the call log as a transparency log, where it is the standard answer.

## Decisions

- **The head signs a plain hash of the whole item set.** `PolicyHead { format, fabric, version,
  issued, not_after, directories, items_hash }`, where `items_hash` is blake3 over the canonical,
  sorted items (domain-separated). Signed by the root, as now.
- **Hosts and directories hold the whole policy.** No host slices.
- **Host updates are deltas without proofs:** `policy_update { head, fresh, changed: [Item],
  removed: [ItemKey] }`. The host applies it to its full copy, recomputes `items_hash`, and checks
  the root's signature on the new head. Any mismatch or gap → fetch the whole policy. A mix of
  versions is impossible, because the one signature covers the whole set.
- **Each service entry is root-signed on its own**, for callers: `SignedEntry { format, fabric,
  version, name, service, alg, sig }` over its own domain-separation prefix, where `version` is the
  head version at which the entry last changed. The admin re-signs only the entries an edit
  changes. The service item in the policy *is* the signed entry, so `items_hash` covers it too.
- **A view is a list of signed entries** (marked call/read) plus the head and `Fresh`; each entry
  verifies on its own under the root. A caller keeps the newest `version` per entry and never takes
  an older one. A caller holding a stale entry is safe: the host decides every call from its full,
  current policy and refuses one it doesn't serve.
- **Removed:** `merkle.rs`, `InclusionProof`, `MultiProof`, `ProofPath`, `Slice` and slice frames,
  and proof fields in views and updates. `DirectoryRequest::slice` → `policy {have}` (whole) with
  `policy_update` answers and subscription frames.

## Acceptance

- [x] No Merkle code or proof types remain in `library/services/` or the frames.
- [x] A host applies an update to its full copy and verifies it with one root signature; a tampered,
      missing or extra item makes it fetch the whole policy (tests, including proptests over random
      edits).
- [x] A view entry verifies alone; a forged entry, one from another fabric, or an older version than
      the one held is refused.
- [x] `policy_sizes` reports: whole policy at 100 / 1k / 5k services, an update for one changed
      service, one ban, and a 25-entry view; the bench model and REPORT use them.
- [x] Cards 36 and 37, fabric.md and protocol.md say "the root signs the policy, and each service
      entry"; no slices or proofs remain in them.
- [x] `cargo test --workspace`, `make lint`, `cargo fmt --all --check`, `make demo` green.

## Notes

**Built (2026-09-24, branch `worker/36d-no-merkle`).**

- **Modules.** `entry` (`SignedEntry`, `ENTRY_V1`, `ENTRY_CONTEXT` = `wires/service-entry/v1\0`;
  `sign(root, version, name, service)`, `verify(root)`, `is_for`), `head` (`items_hash:
  ItemsHash`; `ItemsHash::of(items)` = blake3 of `wires/policy-items/v1\0` ‖ canonical JSON array
  of the items), `item` (`Item::Service(SignedEntry)`: serialized as the entry's fields beside
  `"kind":"service"`), `signed_policy` (`Policy`, `SignedPolicy`, `view_for`), `policy_update`
  (`PolicyUpdate`, `update_from`, `apply`), `view` (renamed from `parts`: `View`, `ViewEntry`,
  `ViewUpdate`). `merkle.rs` and `Slice`/`SliceUpdate` are gone; `Error::BadProof` became
  `Error::ItemsMismatch` ("the items are not the ones the policy head commits to").
- **Signing.** `Policy::items(root, previous)` now signs the service entries, so it takes the
  root. `Policy::sign(root)` signs every entry at the policy's version; `Policy::sign_after(root,
  previous)` keeps each entry of `previous` whose fabric, name and `Service` are unchanged (and
  whose version is not above the new one), with its signature and version. `wires/admin`'s one
  edit path (`edit_policy`) uses `sign_after` the stored policy; a wires test checks an edit keeps
  an untouched entry's signature and version, and a role edit changes no entry.
- **Verify.** `SignedPolicy::verify(root)` is the one entry point: head (alg, format, fabric pin,
  signature), items strictly in key order, `ItemsHash` (`ItemsMismatch`), every entry from this
  fabric at a version ≤ the head's, every entry's own signature, then `Policy::validate`. Its
  cost at 5k services is 5k ed25519 verifies (a quarter-second or so); `apply` skips the held
  entries (the hash under the new head covers them) and checks only the changed ones, through
  the crate-private `check_items`.
- **Updates.** `new.update_from(&old)` → `PolicyUpdate {head, changed: [Item], removed:
  [ItemKey]}`. `old.apply(&update, root)`: same fabric and not older, removed keys held and named
  once, no key twice, then the rebuilt policy passes `check_items`. Any error leaves the held
  copy untouched: the holder asks for the whole policy. Views: `View::update_to(newer)` →
  `ViewUpdate {head, changed: [ViewEntry], removed: [ServiceName]}`; `View::apply` also refuses a
  changed entry whose version is below the held one's (equal is accepted: marks can change without
  the entry). A directory can still withhold an entry from a view (no hash covers a view); that is
  the accepted trade-off: the host decides every call from its full policy.
- **Frames** (`library/directory/frames.rs`). `wires/directory/1`: `hello`, `publish`, `head {}`,
  `policy {have}` → `policy {policy, fresh}` | `policy_update {update, fresh}` | `current {fresh}`
  (the permanent whole-policy fetch; `policy_update` defined, not sent yet), `view {have, query?}`
  → `view {view, fresh}` | `view_update {update, fresh}` | `current`, `resolve {service}` → a
  one-entry or empty `view`, `denied`. `slice` is gone. `wires/directory-sub/1`: `subscribe {kind:
  policy | replica | view, have}` (no `roles`); frames `policy`, `policy_update`, `view`,
  `view_update`, `fresh`, `denied`. **Deviation:** the `replica` frame is gone; replicas receive
  `policy {policy, fresh}` like a host (the same content), so `serve.rs` changed one variant name.
  Frame payloads nest the library type (`{update, fresh}`, `{view, fresh}`), as the other frames
  do, rather than flattening `head`/`changed` into the frame.
- **Not wired** (as asked): the directory still refuses `policy`/`view` subscriptions and
  `view`/`resolve` requests (`denied`), and never sends `policy_update`; hosts still use the 36b
  `refresh_loop`. 36c and 37 build on the functions above.
- **Measured** (`cargo run -q --release -p library --example policy_sizes`; frames include the
  `Fresh`):

  | | 100 services, 30 bans | 1k, 300 bans | 5k, 1,500 bans |
  |---|---|---|---|
  | whole policy (items) | 67.4 KB (152) | 667 KB (1,502) | 3.33 MB (7,502) |
  | its `policy` frame (a host's first sync) | 67.9 KB | 667 KB | 3.33 MB |
  | `policy_update`, one changed service | 1,669 B | 1,669 B | 1,669 B |
  | `policy_update`, one new ban | 1,183 B | 1,183 B | 1,183 B |
  | `fresh` beat frame | 475 B | 475 B | 475 B |
  | view of 25 services (`view` frame) | 16.8 KB | 16.8 KB | 16.8 KB |

  The head is 540 B, a `Fresh` 446 B, a signed service entry 610 B (318 B unsigned: the entry's
  signature, fabric and version cost about 290 B), a role item 101 B, a ban item 115 B. Updates
  no longer depend on fabric size. `bench/state-scale/model.py` reproduces the whole-policy sizes
  within 1%; with them a host receives 140 KB (team) to 280 KB (*large*) a day after its first
  sync, and a caller about 25 KB.
- **Lines.** In `library/` and `wires/`: 2,189 removed, 1,806 added (`merkle.rs` 846 and
  `parts.rs` 729 gone; `entry.rs` 295, `view.rs` 428 and `policy_update.rs` 326 new, over half
  of it tests).
- **Outside my lane** (small wording fixes so no doc still promises host slices): `CLAUDE.md`
  (overview paragraph), `docs/board/README.md` (roles row, lanes row, build plan), `docs/usage.md`
  (limits and roadmap), card 29 (one line). Card 09 untouched.
- **Checks:** `cargo test --workspace` 613 passed, 0 failed; `make lint` clean; `cargo fmt --all
  --check` clean; `make demo` all `[ok]` (revoke: exit 77, 0 bytes out; 209 s wall clock).

