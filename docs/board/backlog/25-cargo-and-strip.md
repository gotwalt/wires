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

- [ ] Remove: `MODULE.bazel`, `MODULE.bazel.lock`, `MODULE.aspect`, `REPO.bazel`, `.bazelrc`, `.bazelversion`, `.bazelignore`, every `BUILD`, `tools/` (format, lint, oci, platforms, transitions, preset, multitool lock, workspace_status, downloader.cfg), `.aspect/`, gazelle config, `.envrc` (direnv for Bazel tools), `.devcontainer/` (a Bazel dev image; recreate only if wanted).
- [ ] Cargo: the `library` and `wires` crates keep their flat layout via `[lib] path` / `[[bin]] path` (already declared); `wires_dev` becomes a **Cargo feature** `dev-mock-idp` (`cargo build --features dev-mock-idp`). `#[path]` modules in `library` stay or become normal modules; choose the simpler option.
- [ ] Tests: `cargo test --workspace` must run everything `bazel test //...` did, doctests included. Compare test counts before and after and record them in Notes.
- [ ] Images: one multi-stage `Dockerfile` (build on `rust:1.90`, copy the binary into `gcr.io/distroless/cc`), which builds natively on either architecture. Drop the Zig cross-compile. Record in Notes whether `cargo-zigbuild` is worth adding later; don't add it now.
- [ ] Dev loop: a `Makefile` of ≤ 30 lines (`build`, `test`, `lint` = clippy + shellcheck, `fmt`, `demo`, `image`), or `justfile` if the human prefers; a `.githooks/pre-commit` that runs `cargo fmt --check` on staged Rust. `.clippy.toml`, `rustfmt.toml`, `.shellcheckrc` stay.
- [ ] Scripts: `.scripts/*.sh` and `bench/*.sh` build with `cargo build --release [--features dev-mock-idp]` and use `target/…` paths.
- [ ] `CLAUDE.md`: rewrite Build System, Adding Dependencies (plain `cargo add`; `Cargo.lock` committed), Dev Environment, Containers and Architecture for Cargo. Keep the Development Approach (types → tests → impl → doctests → readability) and conventions.
- [ ] `.github/workflows/weekly_tag.yaml`: remove (the version stamping it feeds was Bazel's). If there's no CI at all, add a minimal one (`cargo fmt --check`, `clippy -D warnings`, `test`) only if the human agrees; otherwise note it.

## Part B — code and files the product no longer uses (audit, then remove)

Verify each is unused on the current tree before removing it; if something is still referenced, say where in Notes and leave it.

- [ ] **Grants and capability tickets.** `serve host.json` never checks grants (card 13); roles replace them. Candidates: `library` `grant.rs`, `ticket.rs` (`CapabilityTicket`), the `grant` field of `Frame::Handshake`, `ServeConfig.require_grant`, `wires advanced grant`, `tools.json` ticket targets (`ToolTarget::Ticket`), and `tools add --ticket`.
- [ ] **The CRL.** `wires remove` (roster re-key) supersedes per-host revocation lists. Candidates: `policy.rs` `Crl`, `CrlSource`, `wires advanced revoke`, `crl.json` handling.
- [ ] **Manual targets now that the channel is the directory** (card 15): `tools add --topic-ticket`, `--node` targets, `wires advanced import` of individual credentials (superseded by `join`). Keep aliases in `tools.json` only if something uses them.
- [ ] **`relay/`** (a self-hosted iroh relay): unused by every demo and doc flow (n0 relays are used). Remove the crate. Keep a README line on `--relay-url` for people who self-host iroh-relay upstream.
- [ ] **`.scripts/soak-topic.sh`**: keep only if it still runs against the new surface; otherwise remove.
- [ ] **Docs:** `docs/archive/` (keep, since it's history), but check `docs/committed-roster.md` and `docs/phase2-topics.md` against the code (grants/CRL sections trimmed or marked historical); `docs/deployment.md` (k8s/Docker notes) is updated for the Dockerfile or cut; `docs/testing.md` is rewritten for Cargo.
- [ ] **Plumbing under `wires advanced`:** after the removals, list what's left and whether each command still has a user; drop the ones with none.

## Acceptance

- [ ] `cargo build --workspace`, `cargo test --workspace` (same or explained test count), `cargo clippy --workspace --all-targets -- -D warnings`, `cargo fmt --check` all green.
- [ ] `.scripts/demo-remote-cli.sh --quiet` and `.scripts/demo-push.sh --quiet` green.
- [ ] `docker build .` produces a working image on this Mac (arm64); note that the same Dockerfile builds natively on workbench (x86_64); build it there once.
- [ ] `git ls-files | wc -l` and the Rust LOC before and after recorded in Notes.

## Notes
