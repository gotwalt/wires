# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

"Wires" — a two-crate Rust workspace built with plain Cargo, plus a
`Dockerfile` for a distroless image of the `wires` binary.

**The current assignment (2026-09-22):** agents run CLIs on other machines.
The machine is reached by public key, never by network path. The caller is
authenticated by their IdP, via an ID token bound to the node key and
published as channel metadata. Every call is recorded by the responder on an
E2EE gossip channel that authorized observers can watch without access to
the caller or the machine running the CLI. `wires call` is the CLI-native
path; `wires mcp` is the stdio MCP on-ramp for clients that only speak MCP.
The goal is a sharp demo for the MCP team.

**Read `docs/board/README.md` before planning any work.** It holds the pitch,
the rebuttals it must survive, the demo target, the lanes, and the worker
rules. Cards move `backlog/ → doing/ → review/ → done/`; only the integrator
moves a card to `done/`. Every README or narration sentence must pass the
rebuttal test in `docs/storytelling.md` §1.

Usage lives in `README.md`. Deployment and testing patterns live in
`docs/deployment.md` and `docs/testing.md`. Specs for code that runs:
`docs/committed-roster.md` (membership and revocation) and
`docs/phase2-topics.md` (the encrypted channels). `docs/restart.md` is
history: the phase plan, kill criteria, and non-negotiables (§7 still holds).
**Git history is the archive:** outdated docs are deleted, not moved aside.
The product summary is `docs/executive-summary.md`. The pre-restart prototype is tagged `archive/poc-2026-05`: reference
it freely, but never merge from it. That includes the old HTTP/OAuth
`wires-mcp` gateway, which `wires mcp` replaces; don't port it.

**Case-insensitive FS gotcha:** the package directory is `wires/`. If a new
file shows up in `git status` as `Wires/…`, add it by its lowercase path.

## Build System

Plain Cargo: one workspace, two crates, `Cargo.lock` committed, toolchain
pinned in `rust-toolchain.toml` (1.91.0). The `Makefile` wraps the dev loop
(`make help`).

```bash
cargo build --workspace                      # make build
cargo test --workspace                       # make test (unit + proptest + e2e + doctests)
cargo test -p wires <name>                   # one test (or module path prefix)
cargo clippy --workspace --all-targets -- -D warnings   # make lint (also shellcheck)
cargo fmt --all                              # make fmt (also shfmt)
cargo build --release -p wires               # the shipped binary: target/release/wires
cargo build --release -p wires --features dev-mock-idp  # + hidden `wires dev-mock-idp` (demo only)
.scripts/demo-remote-cli.sh --quiet          # make demo: the self-asserting loopback demo
docker build .                               # make image: distroless image, native arch
```

`dev-mock-idp` is a Cargo feature of the `wires` crate: a hermetic loopback
OIDC issuer for the demo script. It is never in a release or the image.

## Dev Environment Setup

1. Install Rust with [rustup](https://rustup.rs); `rust-toolchain.toml` pulls
   the pinned toolchain (with clippy and rustfmt) on first use.
2. `brew install shellcheck shfmt` for the shell half of `make lint` / `make fmt`.
3. `make hooks` (sets `core.hooksPath` to `.githooks`): the pre-commit hook
   refuses staged Rust that isn't `rustfmt`-clean.

## Adding Dependencies

`cargo add -p <crate> <dep>` (or add it to root `[workspace.dependencies]`
and reference it with `{ workspace = true }` when both crates share it;
test-only deps go under `[dev-dependencies]`). Commit the `Cargo.lock`
change. Don't run `cargo update` wholesale as a side effect: it bumps every
crate.

## Development Approach

Work type-driven, in this strict order (don't skip ahead):

1. **Types + signatures first.** Define every type and public function with a
   compiling stub body (`todo!("…")`). Give each public module, type, field, and
   function a correct `///` docstring up front.
2. **Tests before implementations.** Write the full suite against those
   signatures — **property tests (`proptest`)** *and* example/known-answer
   **unit tests** — so it compiles and fails (red).
3. **Implement** until `cargo test --workspace` is green.
4. **Doctests.** Add runnable `///` examples on the public API (`cargo test`
   runs them).
5. **Readability pass.** Re-assess module split, names, and re-exports; refactor.

Conventions:
- **Newtypes, not primitives.** No public API exposes a bare `[u8; N]` or
  `Vec<u8>`; wrap identifiers/blobs in newtypes (e.g. `NodeId`, `Signature`) so
  the type system tells them apart.
- **Docstrings everywhere**, with doctests wherever an example is feasible.
- **One concept per module**; `lib.rs` re-exports the public surface; keep
  internals `pub(crate)`/private (e.g. the `codec` module, `RosterHeadBody`).
- Run `make lint` (clippy + shellcheck) and `make fmt` before committing.

Each `library` module is a worked example of the above.

## Containers

One multi-stage `Dockerfile`: build on `rust:1.91.0-bookworm`, copy the
binary into `gcr.io/distroless/cc-debian12:nonroot`. It builds natively on the
Docker host's architecture (arm64 on a Mac, x86_64 on workbench); there is no
cross-compile. The image holds only `wires` (enough for the caller side); a
host exposing CLIs needs an image that also has those CLIs.

## Architecture

- `Cargo.toml` / `Cargo.lock` — the workspace. Members are flat top-level
  packages: `library/` (the `library` crate, `[lib] path = "lib.rs"`) and
  `wires/` (the `wires` binary, `[[bin]] path = "main.rs"`). No `src/`
  subdir; the sources are filed by role:
  - `wires/`: `main.rs` is argument parsing and dispatch only; each role owns
    a folder with a `mod.rs` — `admin/` (keystore, the root's offline
    commands), `host/` (`serve`, the session transport, the caller checks, IdP
    policy, audit records, push), `caller/` (`join`, `login`, `call`, `tools`,
    `mcp`, `inbox`), `channel/` (the topic node every role meets on, `watch`);
    `advanced.rs` is the `wires advanced` plumbing dispatch; `e2e/` holds the
    loopback integration tests and `testutil.rs` the shared test fixtures.
    See `docs/board/README.md` § Roles.
  - `library/`: `membership/`, `channel/`, `calls/` are folders only — every
    module is declared at the crate root with `#[path]`, so public paths
    (`library::roster`, …) and the `lib.rs` re-exports don't depend on them.
- `.scripts/` — the self-asserting demo(s) and their fixtures; `bench/` — the
  token benchmark (card 16) and its results.
- Rust edition 2024, toolchain 1.91.0 (`rust-toolchain.toml`).
- Lint: `clippy` (`.clippy.toml`) + `shellcheck` (`.shellcheckrc`). Format:
  `rustfmt` (`rustfmt.toml`) + `shfmt`.
- No CI (decided 2026-09-23): run `make lint test` before pushing.
