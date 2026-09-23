# 06 — Cut the noise; README tells one story

**Lane:** D · **Depends on:** — (README usage sections get a final pass after 01–05 merge) · **Files:** `README.md`, `docs/**` except `docs/board/` and `docs/research/`, `.scripts/` (only deleting obsolete ones), `wires/pair.rs` + its CLI wiring (only if removal is clean)

## Goal

Someone from the MCP team opens the repo and in 60 seconds understands one
idea: **remote CLIs, dialed by key, IdP-authenticated caller, every call on an
observable encrypted channel.** Everything that isn't that is archived or gone.

## Tasks

- [x] **README rewrite.** Lead with the pitch from `docs/board/README.md` (verbatim
      or tighter). Then: the 90-second demo (placeholder until card 07 lands), the
      "why not Tailscale / why not an MCP gateway / why CLIs" table, quickstart,
      and *then* reference material. Topics/group chat is demoted to "the channel
      the calls land on" — not a second product. Keep the layer-model thesis at the
      bottom only if it still reads true; otherwise move it to `docs/archive/`.
      Every sentence must survive the storytelling.md §1 rebuttal test; delete any
      that don't. No "substrate", "fabric" (in prose), "capability-gated".
- [x] **docs/ triage.** Move to `docs/archive/` with a one-line header saying why
      it's archived: `fabric-vision.md`, `provable-fabric-inclusion.md`,
      `superpowers/plans/2026-05-25-committed-roster.md`, `rust-bazel-layout.md` if
      superseded by CLAUDE.md. Keep `committed-roster.md` and `phase2-topics.md` as
      specs (they describe code that runs). Fix links.
- [x] **restart.md reconcile.** Add a dated §0 at the top: "2026-09-22 — pitch
      re-sharpened; see docs/board". Amend §2 to record that the CLI-efficiency
      argument is back *as a secondary leg* (CLIs vs MCP tool schemas/results), with
      the reason, rather than deleting the old reasoning.
- [x] **`pair`**: if `wires pair` isn't used by any demo or test in the new story,
      remove it (code, CLI, docs). If removal isn't clean, leave it and note why.
- [x] **Old demo gif**: keep until card 08 replaces it; note in Notes.
- [ ] Commit `docs/research/agent-comms-2026-08/` as-is (currently untracked).

## Acceptance

- [x] `bazel test //...` still green; no dead links in README (`grep -o '](docs/[^)]*)'` all exist).
- [x] README's first screen contains the pitch, the demo, and the rebuttal table — nothing else.

## Notes

- **Not done: `docs/research/agent-comms-2026-08/`.** It is untracked in the main
  checkout and doesn't exist in this worktree. Integrator: `git add` it as-is on
  the integration branch.
- **README shape.** First screen = pitch (board text, verbatim), "The demo"
  (the board's four steps, marked *Status: in progress*), and a four-row
  "Why not…" table (Tailscale, MCP gateway, MCP vs CLIs, OAuth per server).
  Then Quickstart (steps 1–2 run today; 3–5 are the target flow, marked in
  progress, using only flags named on cards 01–05), What runs today (the four
  demo scripts), The channel the calls land on (topics, demoted), then
  `# Reference` (the old Usage material, fabric prose removed). A
  `<!-- card 07 -->` placeholder sits in *What runs today* for
  `demo-remote-cli.sh`. Once 01–05 merge, the Reference section needs the
  new commands added and the quickstart status marker removed.
- **Assumed on the quickstart** (verify at merge): `serve` keeps `--trust-root`,
  and an inclusion-only `--expose` responder needs `--allow-any-member` (per card 01).
  `wires tools add … --node` per card 03; `wires login --topic` per card 04.
- **Cut for failing the rebuttal test**: the old one-liner ("private,
  end-to-end-encrypted group chat… any MCP server can be dialed into it");
  "No OAuth bolt-on, no bearer token pasted into a config file, no inbound port"
  (storytelling §1: *Steal the config*, *No inbound port*); "the agent holds
  only that grant, never the tool's secrets" (*The tool that isn't in the box*);
  the data-sovereignty paragraph and "Where this is going" (off-pitch); the
  board's "measurably cheaper" became "meaningfully more efficient" since we
  have no measurement; "revoked at every responder" gained "holding the new head".
- **Thesis archived** to `docs/archive/session-layer-thesis.md`: the frame
  vocabulary was never built and "multi-party as session fan-out" never shipped,
  so it no longer read true.
- **Archived**: fabric-vision, provable-fabric-inclusion, the executed
  2026-05-25 roster plan (renamed `2026-05-25-committed-roster-plan.md`),
  rust-bazel-layout (superseded by CLAUDE.md's flat, hand-written BUILDs).
  Each has a one-line header; links fixed in committed-roster.md and inside archive.
- **`pair` removed.** Nothing in the new story, the demos, or other tests used it.
  The change was `wires/pair.rs` (and its own tests) plus its subcommand wiring
  in `wires/main.rs`: `mod pair`, the `Pair` variant, the `Pair*Args` structs,
  the dispatch arm, and `pair_*_cmd`. `transport::bind_with_alpn` is still used
  by `bind`, so nothing else went dead. Docs: README command table and
  deployment.md. Lanes A/B/C/F: expect a trivial conflict in `main.rs` only if
  you touched those lines.
- **Old gif** (`docs/demo-revoke.gif`) kept, now under *What runs today*
  with a note that the remote-CLI recording (card 08) replaces it.
- **Stale outside my lane**: CLAUDE.md still says "the session-layer thesis …
  live[s] in README.md" and points to restart.md's 2026-08-13 pitch. The
  integrator should update it.
- **Base commit 2f57378 doesn't build from a clean checkout**: `wires/main.rs`
  declares `mod tools;` but `wires/tools.rs` was never committed. It sits
  untracked in the main checkout, which also shows it as `Wires/tools.rs`
  (case-insensitive FS). I verified green (`bazel test //...`: 5/5, clippy clean)
  with an untracked copy of that file and did not commit it. Integrator:
  commit `wires/tools.rs` (lowercase path).
