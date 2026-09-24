# 36d — Simpler policy integrity: signed document + signed entries, no Merkle tree

**Lane:** D2 · **Depends on:** 36b · **Status:** backlog, decided 2026-09-24 · **Files:** `library/services/{head,item,signed_policy,parts,merkle}.rs`, `library/directory/frames.rs`, `library/examples/policy_sizes.rs`, `wires/directory/`, card 36, card 37, fabric.md, protocol.md

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

- [ ] No Merkle code or proof types remain in `library/services/` or the frames.
- [ ] A host applies an update to its full copy and verifies it with one root signature; a tampered,
      missing or extra item makes it fetch the whole policy (tests, including proptests over random
      edits).
- [ ] A view entry verifies alone; a forged entry, one from another fabric, or an older version than
      the one held is refused.
- [ ] `policy_sizes` reports: whole policy at 100 / 1k / 5k services, an update for one changed
      service, one ban, and a 25-entry view; the bench model and REPORT use them.
- [ ] Cards 36 and 37, fabric.md and protocol.md say "the root signs the policy, and each service
      entry"; no slices or proofs remain in them.
- [ ] `cargo test --workspace`, `make lint`, `cargo fmt --all --check`, `make demo` green.

## Notes
