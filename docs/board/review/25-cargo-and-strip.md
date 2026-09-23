# 25 — Down to essentials: plain Cargo, and remove what the product no longer uses

**Lane:** X · **Depends on:** 23 and 24 merged (this touches every package's build and much of `wires/`; don't run it alongside feature lanes) · **Files:** repo-wide

## Why (the human, 2026-09-23: "is bazel getting us anything here vs normal rust build?")

The repo is single-language Rust, three crates, with **no remote cache and no CI** beyond a weekly tag job. What Bazel was supposed to give, and what happened this project:

| Promise | Reality |
|---|---|
| Hermetic toolchains (pinned LLVM on macOS, Zig for Linux cross) | Broke twice: an Xcode bump broke the host link (see memory note on host lld), and the Linux x86_64 cross-compile fails in `curve25519-dalek` (card 08). |
| OCI images via `rules_oci` | Only ever built for arm64; workbench had to build natively instead. |
| One lint/format entry point | `cargo clippy`, `cargo fmt`, `shellcheck`, `shfmt` do the same with less. |
| Monorepo scale (multi-language, remote cache) | Unused. |

**Costs paid:** `generate-lockfile` bumping every crate (twice), hand-kept BUILD files mirroring `Cargo.toml`, a separate `//wires:wires_dev` target for a feature flag, bazelisk installed on workbench, ~6 min cold builds for every parallel worktree, sandbox paths deep enough to hit the macOS 104-byte socket limit.

## Part A — Bazel → Cargo

- [x] Remove: `MODULE.bazel`, `MODULE.bazel.lock`, `MODULE.aspect`, `REPO.bazel`, `.bazelrc`, `.bazelversion`, `.bazelignore`, every `BUILD`, `tools/` (format, lint, oci, platforms, transitions, preset, multitool lock, workspace_status, downloader.cfg), `.aspect/`, gazelle config, `.envrc` (direnv for Bazel tools), `.devcontainer/` (a Bazel dev image; recreate only if wanted).
- [x] Cargo: the `library` and `wires` crates keep their flat layout via `[lib] path` / `[[bin]] path` (already declared); `wires_dev` becomes a **Cargo feature** `dev-mock-idp` (`cargo build --features dev-mock-idp`). `#[path]` modules in `library` stay or become normal modules; choose the simpler option.
- [x] Tests: `cargo test --workspace` must run everything `bazel test //...` did, doctests included. Compare test counts before and after and record them in Notes.
- [x] Images: one multi-stage `Dockerfile` (build on `rust:1.90` → **1.91.0**, see Notes, copy the binary into `gcr.io/distroless/cc`), which builds natively on either architecture. Drop the Zig cross-compile. Record in Notes whether `cargo-zigbuild` is worth adding later; don't add it now.
- [x] Dev loop: a `Makefile` of ≤ 30 lines (`build`, `test`, `lint` = clippy + shellcheck, `fmt`, `demo`, `image`), or `justfile` if the human prefers; a `.githooks/pre-commit` that runs `cargo fmt --check` on staged Rust. `.clippy.toml`, `rustfmt.toml`, `.shellcheckrc` stay.
- [x] Scripts: `.scripts/*.sh` and `bench/*.sh` build with `cargo build --release [--features dev-mock-idp]` and use `target/…` paths.
- [x] `CLAUDE.md`: rewrite Build System, Adding Dependencies (plain `cargo add`; `Cargo.lock` committed), Dev Environment, Containers and Architecture for Cargo. Keep the Development Approach (types → tests → impl → doctests → readability) and conventions.
- [x] `.github/workflows/weekly_tag.yaml`: remove (the version stamping it feeds was Bazel's). **No CI**: the human decided on 2026-09-23 to ignore CI for now, so don't add a workflow.

## Part B — code and files the product no longer uses (audit, then remove)

**Out of scope here:** the channel machinery (topics, gossip, fabric keys, re-keys, announcements, directory). Card 27 removes it as part of the services redesign; don't touch it in this card.

Verify each is unused on the current tree before removing it; if something is still referenced, say where in Notes and leave it.

- [x] **Grants and capability tickets.** `serve host.json` never checks grants (card 13); roles replace them. Candidates: `library` `grant.rs`, `ticket.rs` (`CapabilityTicket`), the `grant` field of `Frame::Handshake`, `ServeConfig.require_grant`, `wires advanced grant`, `tools.json` ticket targets (`ToolTarget::Ticket`), and `tools add --ticket`.
- [x] **The CRL.** `wires remove` (roster re-key) supersedes per-host revocation lists. Candidates: `policy.rs` `Crl`, `CrlSource`, `wires advanced revoke`, `crl.json` handling.
- [x] (partly — see Notes) **Manual targets now that the channel is the directory** (card 15): `tools add --topic-ticket`, `--node` targets, `wires advanced import` of individual credentials (superseded by `join`). Keep aliases in `tools.json` only if something uses them.
- [x] **`relay/`** (a self-hosted iroh relay): unused by every demo and doc flow (n0 relays are used). Remove the crate. Keep a README line on `--relay-url` for people who self-host iroh-relay upstream.
- [x] **`.scripts/soak-topic.sh`**: keep only if it still runs against the new surface; otherwise remove.
- [x] **Plumbing under `wires advanced`:** after the removals, list what's left and whether each command still has a user; drop the ones with none.

## Part C — unused and outdated docs (the human, 2026-09-23)

**Rule: git history is the archive.** A doc that doesn't describe the code as it runs today, or guide current work, is deleted, not moved to `docs/archive/`. The tag `archive/poc-2026-05` and the git log keep everything. Default per file (verify before deleting; if a doc is still linked from something kept, fix the link or keep the doc and say why):

| File | Default | Why |
|---|---|---|
| `docs/archive/*`, `docs/demo-revoke.gif`, `docs/research/` | ✅ **deleted 2026-09-23** (the human: "git history provides the backup") | — |
| `docs/restart.md` | **delete**, after carrying its still-live content (the §7 non-negotiables and kill criteria) into `docs/board/README.md` in ≤ 10 lines | The phase plan is superseded by the board. |
| `docs/committed-roster.md`, `docs/phase2-topics.md` | **rewrite into one current spec** (`docs/protocol.md`): roster, re-key, channel, records, as built; drop grants/CRL/Phase-2 framing | They describe removed features and old names. |
| `docs/deployment.md` | rewrite for the Dockerfile + `wires serve host.json`, or delete if under ~20 useful lines | k8s/Bazel-era. |
| `docs/testing.md` | rewrite for Cargo (short) | Bazel-era. |
| `docs/storytelling.md` | keep, trimmed to the rebuttal test (§1) and anything the board references | It's still how pitch sentences get checked. |
| `docs/demo.md`, `docs/agent-sandbox.md` | keep; update commands for Cargo | Current. |
| `docs/board/done/*` | keep until after the demo; then optionally collapse into `docs/board/HISTORY.md` (one paragraph per card) | Cards carry decisions and Notes still being referenced. |
| `CLAUDE.md`, `README.md` | fix every link to a deleted doc | — |

- [x] After Part C, `git ls-files docs | wc -l` and a dead-link check (`grep -o '](docs/[^)#]*' -r README.md CLAUDE.md docs | …`) are recorded in Notes; no link points at a deleted file.

## Acceptance

- [x] `cargo build --workspace`, `cargo test --workspace` (same or explained test count), `cargo clippy --workspace --all-targets -- -D warnings`, `cargo fmt --check` all green.
- [x] `.scripts/demo-remote-cli.sh --quiet` green. **Open:** `.scripts/demo-push.sh --quiet` — the script arrived on `aaron/remote-cli` after this lane branched and merging it here was refused by the sandbox; convert and run at merge (recipe below).
- [x] `docker build .` produces a working image on this Mac (arm64). **Open:** build it once on workbench (x86_64); not done from this lane (no workbench access asked for).
- [x] `git ls-files | wc -l` and the Rust LOC before and after recorded in Notes.

## Notes

*Lane X, 2026-09-23. Branch commits: Bazel → Cargo; strip grants/tickets/CRL; docs.*

**Numbers** (before = `7d34d3b`, after = this branch; the card-24/26a files are not in either):

| | before | after |
|---|---|---|
| tracked files | 178 | 143 |
| `docs/` files | 38 | 36 (restart, committed-roster, phase2-topics out; protocol.md in) |
| `.rs` files / Rust LOC | 78 / 47,485 | 75 / 45,557 |
| tests: `library` unit + proptest | 295 (`//library:library_test`) | 281 |
| tests: `wires` unit + e2e | 413 (`//wires:wires_test`) | 382 |
| doctests | 54 (`//library:library_doc_test`) | 47 |
| other | `//relay:relay_test` 1, `//tools:preset.update_test` (Bazel infra) | — (crate / infra removed) |

`cargo test --workspace` on the tree *before* the Part B removals ran exactly 295 + 413 + 54: the
same suite as `bazel test //...`. Every test lost after that tests a removed feature (grant
minting/acceptance/scopes, capability tickets and `tools add --ticket|--topic-ticket`, the CRL and
`revoke`, `keygen`), plus the relay's one test. One wires test was added
(`removed_plumbing_is_gone`). `e2e::directory::a_joined_caller_finds_calls_…` failed once under
`bazel test` and once under a loaded `cargo test` (gossip timing) and passed alone; channel code,
card 27 deletes it.

**Part A.**
- Toolchain: `rust-toolchain.toml` pins **1.91.0** (what `rules_rust` used). The card said
  `rust:1.90`, but iroh 1.0.3 needs 1.91, so the Dockerfile builds on `rust:1.91.0-bookworm`.
  Pinning also fixes clippy's lint set; `rust-version = "1.91"` is in the workspace.
- Bazel's `aspect lint` never ran clippy on test targets; `--all-targets` found 6 small lints in
  tests (`cloned_ref_to_slice_refs`, one `type_complexity`), fixed in `inbox.rs`, `login.rs`,
  `mcp.rs`, `host/push.rs` (tests only).
- `#[path]` modules in `library` stay (simplest; no churn).
- Image: `gcr.io/distroless/cc-debian12:nonroot`, 22 MB, arm64 here; `wires --version` and
  `wires id` run in it. BuildKit cache mounts keep rebuilds fast. **cargo-zigbuild:** not worth it
  now; every consumer (Mac, workbench) builds natively. Revisit only for an x86_64 artifact built
  on a Mac without Docker.
- `shellcheck`/`shfmt` are no longer provisioned (they came from Bazel's multitool):
  `brew install shellcheck shfmt` (in CLAUDE.md). I could not run them here.
- `.gitattributes` now only marks `Cargo.lock` generated; `.gitignore` drops the Bazel entries
  (keeps `/bazel-*` so an old checkout's symlinks stay ignored) and still ignores `.claude/*`.
- `soak-topic.sh` removed: a channel soak driven by `advanced keygen/member/import/publish`.

**Part B — what went, what stayed.**
- Gone: `library` `grant.rs` (`Grant`, `Scope`), `ticket.rs` (`CapabilityTicket`), `Crl`,
  `check_accept`, `Error::Revoked`; `check_inclusion` lost its `crl` argument; `AlgorithmId`
  moved to `identity.rs`; `Frame::Handshake.grant` (an old dialer's extra field is ignored on
  decode). `wires`: `ServeConfig.{require_grant, crl}`, `CrlSource`, `serve --crl-json/--crl-file`,
  `advanced grant | revoke | keygen`, `ToolTarget::Ticket`, `tools add --ticket | --topic-ticket`,
  `keystore::{crl_source, read/write_crl_text}`, `crl.json`. With no tickets, every dial now
  verifies the responder's ack membership (the old "ticketless" path is the only path).
- `relay/` removed; README and deployment.md point self-hosters at upstream `iroh-relay` +
  `--relay-url`.
- **Kept, with reason:**
  - `ToolTarget::Node` / `tools add --node --addr`: the directory resolves to it internally
    (`caller/resolve.rs`), and `bench/wires-up.sh` pins `gh` by node + loopback address.
  - `advanced import` and `advanced member`: channel code this card must not touch names them as
    the remedy in ~15 user-facing errors (`channel/context.rs`, `local.rs`, `printer.rs`,
    `replay.rs`, `watch.rs`, `admin/keystore.rs` fabric-key parse). `join` covers them in
    practice; card 27 deletes fabric keys and can drop both with those messages.
  - `advanced roster` (commits mint/seal fabric keys) and `advanced publish` (channel): card 27.
  - `advanced keygen` had no user once `bench/wires-up.sh` moved to `init`/`invite`/`join` (the
    responder is the admin, so its head never lags); the keystore's "no key" errors now say
    `wires id` / `wires init`.
- Small out-of-lane edits: `channel/context.rs` (preflight lost its grant arg),
  `membership/invite.rs` (`check_inclusion` arity), e2e call sites (`call_on` arity), and some
  doc comments naming grants/CRL/deleted docs.

**Part C.** `restart.md` deleted (non-negotiables + kill criteria are the top of the board README,
9 lines); `committed-roster.md` + `phase2-topics.md` → `docs/protocol.md` (as built; §§6–8 flagged
for card 27); `deployment.md` rewritten for the Dockerfile (k8s relay manifest gone);
`testing.md` rewritten for Cargo; `storytelling.md` trimmed to §1 + script conventions. Dead-link
check (every relative `](…)` in tracked `.md`, not just `](docs/`): none, apart from the two
`](docs/[^` grep snippets in cards 06/25. Fixed two older dead links on the way
(`done/22` → `backlog/18`, executive summary → `done/22`).

**Merge recipe: card 24's scripts, Bazel → Cargo** (mechanical; no `advanced`/`--ticket`/CRL
flags are used in any of them):
- `.scripts/demo-push.sh`: replace
  `WIRES="${WIRES_BIN:-$repo/bazel-bin/wires/wires}"` → `$repo/target/release/wires`,
  `WIRES_DEV="${WIRES_DEV_BIN:-$repo/bazel-bin/wires/wires_dev}"` →
  `$repo/target/release/wires-mock-idp`, and the `bazel build //wires:wires //wires:wires_dev`
  block (lines ~125–128) with the one in `demo-remote-cli.sh`:
  `cargo build -q --release -p wires --features dev-mock-idp; cp -f target/release/wires "$WIRES_DEV"; cargo build -q --release -p wires`
  (guarded by `[ -z "${WIRES_BIN:-}" ]`; the feature build must come first, since both land at
  `target/release/wires`). Update the header comment's `//wires:wires_dev` mention.
- `bench/push/run.sh`: the usage line `bazel build //wires && …` → drop the prefix; replace
  `[ -x "$repo/bazel-bin/wires/wires" ] || (cd "$repo" && bazel build //wires)` +
  `cp "$repo/bazel-bin/wires/wires" …` with `(cd "$repo" && cargo build -q --release -p wires)` +
  `cp -f "$repo/target/release/wires" …` (as in `bench/run.sh`).
- `bench/push/up.sh`: the error hint → `cargo build --release -p wires; copy target/release/wires there`.
- `docs/demo.md` push segment: any `bazel build`/`bazel-bin` → the cargo equivalents above.
- 26a (`library/calls/call_log.rs`, `wires/host/{call_log,otlp}.rs`): no new crates, so no
  manifest work; it must adopt this branch's `ServeConfig` (no `require_grant`/`crl`),
  `call_on`/`dial_session` (no `grant`/`ticketless` args) and `check_inclusion` (no `crl`) if it
  calls them. Expect small conflicts in `wires/host/serve.rs` (26a's `audit.otlp` wiring vs the
  removed `--crl-*` flags) and in the board README lanes table.
