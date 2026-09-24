# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

"Wires" — a Rust workspace built with plain Cargo (`library`, `wires`, and
the language bindings `wires-ffi` (Python, via UniFFI) and `wires-node`
(TypeScript, via napi-rs)), plus a `Dockerfile` for a distroless image of
the `wires` binary.

**The current assignment (2026-09-22, reshaped by card 27):** agents run
CLIs on other machines, by **service name**. The machine is reached by public
key, never by network path. Each node is admitted by its root-signed badge;
one admin-signed, versioned policy says which IdPs are trusted, which roles
exist, which services exist, which hosts run each, who may call and read
each, who is banned, and which nodes are directories; the admin publishes it
by key to the directories, hosts and callers fetch it from one, and every
host decides every call from its copy. The caller is
authenticated by their IdP, via an ID token bound to the node key and
presented in the session handshake; every role needs that verified identity
(there is no built-in `member` role), and every role matcher names its
issuer. Every call is recorded by the host in its own signed, hash-linked
log. Agents can't observe each other's work: the isolation boundary is the
verified person (IdP principal), so a caller sees its own person's records,
and the readers the registry names see a service's records in full with
`wires watch`, for logging and compliance. Nothing is broadcast; what every
member still learns about the others (the whole signed policy) is cards
36c–37's to fix, by giving each host its slice and each caller its view
(`docs/fabric.md`). `wires call` is the CLI-native path and the source of the token
savings; `wires mcp` (stdio) and `wires gateway` (remote, e.g. Claude.ai) serve
the same services as MCP, so wires works in the clients people already use
for remote tool calling, with the same identity, registry and record (MCP
compatibility is a goal, not a fallback). The goal is a sharp demo for the
MCP team.

**What outranks what:** the premise outranks the docs, and the docs outrank
the code. When the code disagrees with `docs/protocol.md`, the code is the
bug, unless the doc breaks the premise.

**Read `docs/board/README.md` before planning any work.** It holds the pitch,
the rebuttals it must survive, the demo target, the lanes, and the worker
rules. Cards move `backlog/ → doing/ → review/ → done/`; only the integrator
moves a card to `done/`. Every README or narration sentence must pass the
rebuttal test in `docs/storytelling.md` §1.

The pitch lives in `README.md`; usage (roles, walkthrough, reference) in `docs/usage.md`. Deployment and testing patterns live in
`docs/deployment.md` and `docs/testing.md`. The spec for the code that runs
(membership, the signed policy and the directory, the session handshake and gate,
push, the call log and record stream, hints) is `docs/protocol.md`; the target
architecture (how the fabric is hosted, persisted and synced, via a directory)
is `docs/fabric.md`. The
non-negotiables and kill criteria are at the top of `docs/board/README.md`.
**Git history is the archive:** outdated docs are deleted, not moved aside.
The product summary is `docs/executive-summary.md`. The pre-restart prototype is tagged `archive/poc-2026-05`: reference
it freely, but never merge from it. That includes the old HTTP/OAuth
`wires-mcp` gateway; `wires gateway` (card 30) is its from-scratch
replacement on the current identity model.

**Case-insensitive FS gotcha:** the package directory is `wires/`. If a new
file shows up in `git status` as `Wires/…`, add it by its lowercase path.

## Build System

Plain Cargo: one workspace, four crates (`library`, `wires`, `wires-ffi`,
`wires-node`), `Cargo.lock` committed, toolchain
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
.scripts/build-python.sh                     # make python: Python bindings into target/python
.scripts/build-node.sh                       # make node: the npm package into target/node/wires
.scripts/demo-native-service.sh --lang python   # make demo-python: a Python-native service, end to end (needs uv)
.scripts/demo-native-service.sh --lang node     # make demo-node: the same in TypeScript (Node >= 22.18)
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
and reference it with `{ workspace = true }` when crates share it;
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
  internals `pub(crate)`/private (e.g. the `codec` module, `SignedBody`).
- Run `make lint` (clippy + shellcheck) and `make fmt` before committing.

Each `library` module is a worked example of the above.

## Containers

One multi-stage `Dockerfile`: build on `rust:1.91.0-bookworm`, copy the
binary into `gcr.io/distroless/cc-debian12:nonroot`. It builds natively on the
Docker host's architecture (arm64 on a Mac, x86_64 on workbench); there is no
cross-compile. The image holds only `wires`: enough for the caller side and
for `wires gateway`, which `deploy/gateway/` (Compose + Cloudflare Tunnel)
runs from it. A host serving CLIs needs an image that also has those CLIs.

## Architecture

- `Cargo.toml` / `Cargo.lock` — the workspace. Members are flat top-level
  packages: `library/` (the `library` crate, `[lib] path = "lib.rs"`) and
  `wires/` (the `wires` library, `lib.rs`, and the `wires` binary,
  `main.rs`, which only calls `wires::run`), and `bindings/` (`wires-ffi`:
  UniFFI bindings of the embedding API, foreign module `wires`; Python
  example in `bindings/python/`) with `bindings/node/` (`wires-node`: the
  napi-rs addon and npm package `wires`; TypeScript example in
  `bindings/node/examples/`). No `src/` subdir; the sources are filed
  by role:
  - `wires/`: `lib.rs` is argument parsing and dispatch, plus the public
    embedding API (`Host`, `Service`, `Call`, `CallIo`: card 33, an app
    serving wires calls in-process); `examples/kv/` is a native service;
    each role owns
    a folder with a `mod.rs` — `admin/` (keystore, `init`/`invite`/`remove`,
    `service`/`role`/`issuer`/`directory add|rm` edits of the signed policy,
    `state push`, `--ttl` /
    `--state-ttl`), `host/` (`serve`,
    `host.json`, the gate over the signed policy, the session transport,
    native services and the embedded `Host`,
    verified identities, the call log and OTLP export, the record stream, push,
    its control sockets and the per-call push capability), `caller/` (`join`, `login`, `services`, `call`
    with service → host failover and the local hints file, `mcp`, `inbox`,
    `watch`), `gateway/` (`wires gateway`: remote MCP over HTTP + OAuth
    for web clients, calling with each user's own ID token), `directory/` (the
    directory mode: `directory.redb`, `wires/directory/1` and
    `wires/directory-sub/1`, the freshness beat and replicas, `directory
    serve`), `policy/` (the signed policy on this node: `policy.json`,
    publishing to and fetching from the directories); `e2e/` holds the loopback integration tests and
    `testutil.rs` the shared test fixtures. See `docs/board/README.md` § Roles.
  - `library/`: `membership/`, `calls/`, `services/`, `directory/` are folders only — every
    module is declared at the crate root with `#[path]`, so public paths
    (`library::signed_policy`, …) and the `lib.rs` re-exports don't depend on them.
- `.scripts/` — the self-asserting demos, their shared helpers (`lib.sh`)
  and fixtures, the bindings builds, and `macos-sign.sh`, which
  `.cargo/config.toml` sets as the macOS `runner` so test and `cargo run`
  binaries are signed with a stable identity (firewall approvals survive
  rebuilds; `WIRES_SIGN_ID=-` skips it). `bench/` — the token benchmark
  (card 16) and its results; `bench/push/` the push-vs-poll benchmark
  (card 24). `deploy/gateway/` — the web gateway's Compose deployment.
  `docs/media/` — the README's demo recording.
- Rust edition 2024, toolchain 1.91.0 (`rust-toolchain.toml`).
- Lint: `clippy` + `shellcheck`, both with default settings. Format:
  `rustfmt` (`rustfmt.toml`) + `shfmt` (tabs, per `.editorconfig`).
- No CI (decided 2026-09-23): run `make lint test` before pushing.
