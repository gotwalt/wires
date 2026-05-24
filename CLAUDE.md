# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

"Wires" — a Bazel monorepo built with **Rust** only. The repo was scaffolded
from Aspect CLI's kitchen-sink preset, then pruned down to the toolchains that
support building/linting/formatting Rust and shell, plus `rules_oci` for
cutting Docker images from Rust binaries. (Go, Python, JavaScript/TypeScript,
Java, C++ as a first-class language, and protobuf were removed.)

The session-layer thesis, the binary layout, and full usage live in
`README.md`. Deployment and testing patterns live in `docs/deployment.md` and
`docs/testing.md`.

## Build System

All builds, tests, and linting go through Bazel. A `Makefile` provides shorthand targets — run `make help` to list them.

```bash
# Build everything
bazel build //...

# Test everything
bazel test //...

# Test a single target
bazel test //path/to:target

# Debug a test (streams output, no caching, long timeout)
bazel test --config=debug //path/to:target

# Lint (shellcheck + clippy)
aspect lint //...

# Format all files (rustfmt + shfmt + buildifier)
format

# Format a single file
format path/to/file

# Regenerate Starlark BUILD files
bazel run gazelle

# Stamped release build
bazel build --config=release //...
```

Rust `BUILD` files are **hand-written** and marked `# gazelle:ignore` (see
`//library`, `//wires`, `//relay`) — gazelle does not own them.

## Dev Environment Setup

Uses `direnv` to put Bazel-managed tools on PATH. After cloning:
1. Install [direnv](https://direnv.net/docs/installation.html)
2. Run `direnv allow`, then `bazel run //tools:bazel_env`
3. Set up pre-commit hooks: `git config core.hooksPath .githooks`

## Adding Dependencies

**Rust** (Bazel-only loop — never `cargo build`/`cargo test`):
1. Add the dep to the package's `Cargo.toml` (and root `[workspace.dependencies]` if shared).
2. Refresh the lockfile with the **Bazel-vendored cargo** — the only cargo invocation:
   `bazel run @rules_rust//tools/upstream_wrapper:cargo -- generate-lockfile`
   (or use the `cargo` that `bazel run //tools:bazel_env` puts on `$PATH`).
3. Hand-edit that package's `BUILD` to add the matching `@crates//:<dep>` to `deps`
   (test-only deps go on the `rust_test` target).

Crate resolution is driven by `rules_rs`, which **reads** the root `Cargo.toml` /
`Cargo.lock` (it does not regenerate the lock — hence step 2). External crates are
exposed under `@crates//:`. Build and test exclusively via `bazel build` / `bazel test`.

## Development Approach

Work type-driven, in this strict order (don't skip ahead):

1. **Types + signatures first.** Define every type and public function with a
   compiling stub body (`todo!("…")`). Give each public module, type, field, and
   function a correct `///` docstring up front.
2. **Tests before implementations.** Write the full suite against those
   signatures — **property tests (`proptest`)** *and* example/known-answer
   **unit tests** — so it compiles and fails (red).
3. **Implement** until `bazel test //...` is green.
4. **Doctests.** Add runnable `///` examples on the public API (a `rust_doc_test`
   target runs them under `bazel test`).
5. **Readability pass.** Re-assess module split, names, and re-exports; refactor.

Conventions:
- **Newtypes, not primitives.** No public API exposes a bare `[u8; N]` or
  `Vec<u8>`; wrap identifiers/blobs in newtypes (e.g. `NodeId`, `Signature`) so
  the type system tells them apart.
- **Docstrings everywhere**, with doctests wherever an example is feasible.
- **One concept per module**; `lib.rs` re-exports the public surface; keep
  internals `pub(crate)`/private (e.g. the `codec` module, `GrantBody`).
- **Bazel-only**: build, test, run, and doctests go through `bazel` (see Adding
  Dependencies for the one lockfile-only cargo touchpoint). Run `make lint`
  (clippy + shellcheck) and `format` (rustfmt) before committing.

Each `//library` module is a worked example of the above.

## Containers (OCI)

Rust binaries are packaged into distroless OCI images via the `rust_image` macro
in `tools/oci/rust_image.bzl`. It cross-compiles to Linux (via the Zig CC
toolchain), layers the binary into a `gcr.io/distroless/base` image, and emits
`*.load` (local `docker load`) and stamped-tag targets.

```bash
# Push all OCI images
make push-containers   # runs every oci_push target
```

## Architecture

- `MODULE.bazel` — Central dependency declaration. Rust (`rules_rust` + `rules_rs`),
  CC toolchains (`toolchains_llvm` for the host, `hermetic_cc_toolchain`/Zig for
  Linux cross-compiles — both retained only to link Rust), `rules_oci`, shell,
  lint/format, and `gazelle` (Starlark BUILD maintenance).
- `Cargo.toml` / `Cargo.lock` — the Rust workspace. Members are flat top-level
  packages: `//library` (the `library` crate), `//wires` (the `wires` binary),
  and `//relay` (the `relay` binary). Each package holds its `*.rs` files
  directly (no `src/` subdir), a `BUILD`, and a `Cargo.toml`.
- `tools/` — Build tooling: formatters (`tools/format/`), linters (`tools/lint/`),
  OCI image macro (`tools/oci/`), platform definitions (`tools/platforms/`),
  platform-transition helpers (`tools/transitions/`).
- `tools/preset.bazelrc` — Auto-generated bazelrc flags (update via `bazel run //tools:preset.update`).
- `.aspect/gazelle/shell.axl` — Orion gazelle extension for shell.
- BUILD file convention: `BUILD` (not `BUILD.bazel`).
- Rust edition: 2024, version 1.90.0.
- Linting: `shellcheck` (shell) + `clippy` (Rust). Formatting: `rustfmt` + `shfmt` + `buildifier`.
- Container base: `gcr.io/distroless/base` (via `rules_oci`).
