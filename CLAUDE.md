# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

"Wires" — a Rust workspace built with plain Cargo (`library`, `wires`, and
the language bindings `wires-ffi` (Python, via UniFFI) and `wires-node`
(TypeScript, via napi-rs)), plus a `Dockerfile` for a distroless image of
the `wires` binary.

**The current assignment (2026-10-05):** agents work best with CLIs, so
wires lets an agent run a CLI that lives on another machine as if it were
local: `wires call <service> -- <args>`. Three
things stop a CLI from being shared across an organization, and wires is
those three and little else. **Who is calling:** the caller signs in with the
org's IdP (`wires login`); the ID token is bound to the node key, presented
in each call's handshake, and verified by the host itself; signing in is the
whole of joining (no badges, no invites): a caller is in the network if its
sign-in carries a verified email and a role in the policy matches it
(`library::check_admitted`, used at every host and directory gate). **How they find it:** one
admin-signed, versioned policy says which IdPs are trusted, which roles
exist, which services exist, which hosts run each, who may call each and who
is removed; directories hold it, hosts hold all of it and decide every call
from their copy, and each caller holds only its view, the services its person
may use (`wires services`). A caller tells a host nothing without a directory's
word, signed within `fresh_secs` (15 minutes by default) by a directory other
than that host, that the host's policy is current (a one-machine network
takes its own word), so calls fail closed with every directory down. A user
never handles a host's key.
**How they reach it:** by public key over iroh, never by network path, with
no port opened and no VPN. One thing a local CLI can't do is also in: a
service can push a message back to its caller (`wires push`, `wires inbox`).
Every service gets its caller's identity (`WIRES_ID_TOKEN` and the verified
claims; `call.id_token()` in a native service). `wires mcp` (stdio) and
`wires gateway` (remote, e.g. Claude on the web) serve the same services to
MCP clients as a **bridge** from existing MCP workflows, not a goal of their
own. The signed call log, OTLP export and `wires watch` are cut for now
(card 40): a host writes one ordinary log line per call, and nothing else
records calls. It is experimental research code, with no backwards
compatibility anywhere. The goal is a sharp demo of agents running remote
CLIs by name, with MCP clients reached through the bridge.

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
(admission and the network string, the signed policy, the directory, the
session handshake and gate, identity, push, the keystore, the known limits)
is `docs/protocol.md`; the
architecture (who runs what, what each node keeps, how the policy moves
through the directories) is `docs/fabric.md`. The
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
pinned in `rust-toolchain.toml` (1.98.1). The `Makefile` wraps the dev loop
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
.scripts/demo-push.sh --quiet                # the push demo: a host messages its caller back
make install                                 # the release `wires` into ~/.cargo/bin
.scripts/build-python.sh                     # make python: Python bindings into target/python
.scripts/build-node.sh                       # make node: the npm package into target/node/wires
.scripts/demo-native-service.sh --lang python   # make demo-python: a Python-native service, end to end (needs uv)
.scripts/demo-native-service.sh --lang node     # make demo-node: the same in TypeScript (Node >= 22.18)
.scripts/demo-example-services.sh --quiet        # make demo-examples: examples/services/ wrappers against stub CLIs
docker build .                               # make image: distroless image, native arch
```

`dev-mock-idp` is a Cargo feature of the `wires` crate: a hermetic loopback
OIDC issuer for the demo scripts and `bench/help/`. It is never in a release
or the image.

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

One multi-stage `Dockerfile`: build on `rust:1.98.1-bookworm`, copy the
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
    serving wires calls in-process); `help.rs` is the help text a model
    reads first (card 38), held by `help_snapshots.rs` against the files in
    `snapshots/`; `clock.rs` and `net.rs` are small shared helpers;
    `examples/kv/` is a native service. Each role owns a folder with a
    `mod.rs` — `admin/` (keystore, `init`, `network` (the network string),
    `remove`/`restore` (person and node bans), the admin's node labels
    (`labels.json`), `service`/`role`/`issuer`/`directory add|rm` edits of
    the signed policy, publishing them, `policy push` and `policy settings`,
    `--policy-ttl`), `host/` (`serve`, `host.json`, the gate over the signed
    policy, the session transport, native services and the embedded `Host`,
    following a directory and the freshness check, verified identities, the
    per-call log line (`call_trace`), push, its control sockets and the
    per-call push capability), `caller/` (`id`, `join <network>`, `login
    [<network>]`, the hidden `dev-mock-idp` (`mock_idp.rs`), the caller's
    view (`view.json`, refreshed whole; `wires mcp` and `inbox --wait`
    poll it every 60 s), `services`, `call` (a service's hosts in random
    order, the next only when a dial fails; `vouch.rs` checks a host's
    proof that a directory vouched for its policy before the caller sends
    anything) and output shaping (`--jq`/`--head`/`--max-bytes`), the local
    hints file, locked mode (`WIRES_LOCKED`: a `wires call` with data on
    stdin is refused), `mcp`, `inbox`), `gateway/` (`wires gateway`: remote
    MCP over HTTP + OAuth for web clients, calling with each user's own ID
    token), `directory/` (the directory mode: `wires/directory/3` and
    `wires/directory-sub/3`, its proof before a caller's token, the
    `Fresh` beat to the hosts that follow it, `directory serve`; its store
    is the node's `policy.json`), `policy/` (the signed policy on this node:
    `policy.json`, publishing to and fetching from the directories); `e2e/` holds the loopback
    integration tests (`first_run.rs` is the README's quick tour) and
    `testutil.rs` the shared test fixtures. See `docs/board/README.md`
    § Roles.
  - `library/`: `network/` (node identity, the network string, admission),
    `calls/` (session frames, the host's proof, IdP tokens, push), `services/` (the signed
    policy, entries, roles, views, freshness) and `directory/` (directory
    frames) are folders only — every module is declared at the crate root
    with `#[path]`, so public paths (`library::signed_policy`, …) and the
    `lib.rs` re-exports don't depend on them.
- `.scripts/` — the self-asserting demos (`demo-remote-cli.sh`,
  `demo-push.sh`, `demo-native-service.sh`), their shared helpers
  (`lib.sh`) and fixtures, the bindings builds, and `macos-sign.sh`, which
  `.cargo/config.toml` sets as the macOS `runner` so test and `cargo run`
  binaries are signed with a stable identity (firewall approvals survive
  rebuilds; `WIRES_SIGN_ID=-` skips it). `bench/` — the token benchmark
  (card 16) and its results; `bench/push/` the push-vs-poll benchmark
  (card 24); `bench/help/` the help-text evaluation (card 38);
  `bench/state-scale/` a dated model of policy size. `deploy/gateway/` —
  the web gateway's Compose deployment. `examples/services/` — example
  services wrapping vendor CLIs (`docs/examples.md`). `docs/board/` — the cards;
  `docs/blog/` — the announcement post.
- Rust edition 2024, toolchain 1.98.1 (`rust-toolchain.toml`).
- Lint: `clippy` + `shellcheck`, both with default settings. Format:
  `rustfmt` (`rustfmt.toml`) + `shfmt` (tabs, per `.editorconfig`).
- No CI (decided 2026-09-23): run `make lint test` before pushing.
