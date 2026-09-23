# 06 — Cut the noise; README tells one story

**Lane:** D · **Depends on:** — (README usage sections get a final pass after 01–05 merge) · **Files:** `README.md`, `docs/**` except `docs/board/` and `docs/research/`, `.scripts/` (only deleting obsolete ones), `wires/pair.rs` + its CLI wiring (only if removal is clean)

## Goal

Someone from the MCP team opens the repo and in 60 seconds understands one
idea: **remote CLIs, dialed by key, IdP-authenticated caller, every call on an
observable encrypted channel.** Everything that isn't that is archived or gone.

## Tasks

- [ ] **README rewrite.** Lead with the pitch from `docs/board/README.md` (verbatim
      or tighter). Then: the 90-second demo (placeholder until card 07 lands), the
      "why not Tailscale / why not an MCP gateway / why CLIs" table, quickstart,
      and *then* reference material. Topics/group chat is demoted to "the channel
      the calls land on" — not a second product. Keep the layer-model thesis at the
      bottom only if it still reads true; otherwise move it to `docs/archive/`.
      Every sentence must survive the storytelling.md §1 rebuttal test; delete any
      that don't. No "substrate", "fabric" (in prose), "capability-gated".
- [ ] **docs/ triage.** Move to `docs/archive/` with a one-line header saying why
      it's archived: `fabric-vision.md`, `provable-fabric-inclusion.md`,
      `superpowers/plans/2026-05-25-committed-roster.md`, `rust-bazel-layout.md` if
      superseded by CLAUDE.md. Keep `committed-roster.md` and `phase2-topics.md` as
      specs (they describe code that runs). Fix links.
- [ ] **restart.md reconcile.** Add a dated §0 at the top: "2026-09-22 — pitch
      re-sharpened; see docs/board". Amend §2 to record that the CLI-efficiency
      argument is back *as a secondary leg* (CLIs vs MCP tool schemas/results), with
      the reason, rather than deleting the old reasoning.
- [ ] **`pair`**: if `wires pair` isn't used by any demo or test in the new story,
      remove it (code, CLI, docs). If removal isn't clean, leave it and note why.
- [ ] **Old demo gif**: keep until card 08 replaces it; note in Notes.
- [ ] Commit `docs/research/agent-comms-2026-08/` as-is (currently untracked).

## Acceptance

- [ ] `bazel test //...` still green; no dead links in README (`grep -o '](docs/[^)]*)'` all exist).
- [ ] README's first screen contains the pitch, the demo, and the rebuttal table — nothing else.

## Notes
