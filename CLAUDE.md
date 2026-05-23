# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

"Wires" — a Bazel monorepo built with **Rust** only. The repo was scaffolded
from Aspect CLI's kitchen-sink preset, then pruned down to the toolchains that
support building/linting/formatting Rust and shell, plus `rules_oci` for
cutting Docker images from Rust binaries. (Go, Python, JavaScript/TypeScript,
Java, C++ as a first-class language, and protobuf were removed.)

The conceptual design lives in `docs/` — see `docs/tools-over-wires.md` (the
session-layer thesis) and `docs/new_plan.md` (the binaries to build).

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

# Regenerate BUILD files
bazel run gazelle        # Starlark
bazel run gazelle_rust   # Rust

# Stamped release build
bazel build --config=release //...
```

## Dev Environment Setup

Uses `direnv` to put Bazel-managed tools on PATH. After cloning:
1. Install [direnv](https://direnv.net/docs/installation.html)
2. Run `direnv allow`, then `bazel run //tools:bazel_env`
3. Set up pre-commit hooks: `git config core.hooksPath .githooks`

## Adding Dependencies

**Rust**: `cargo add <crate>` (uses the hermetic cargo from PATH) → `bazel run gazelle_rust`

Crate resolution is driven by `rules_rs` from the root `Cargo.toml` / `Cargo.lock`
(a Cargo workspace). Crates are exposed under `@crates//:`.

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
  lint/format, and `gazelle` (for `gazelle_rust`).
- `Cargo.toml` / `Cargo.lock` — the Rust workspace; crate members live under `crates/`.
- `tools/` — Build tooling: formatters (`tools/format/`), linters (`tools/lint/`),
  OCI image macro (`tools/oci/`), platform definitions (`tools/platforms/`),
  platform-transition helpers (`tools/transitions/`).
- `tools/preset.bazelrc` — Auto-generated bazelrc flags (update via `bazel run //tools:preset.update`).
- `.aspect/gazelle/shell.axl` — Orion gazelle extension for shell.
- BUILD file convention: `BUILD` (not `BUILD.bazel`).
- Rust edition: 2024, version 1.90.0.
- Linting: `shellcheck` (shell) + `clippy` (Rust). Formatting: `rustfmt` + `shfmt` + `buildifier`.
- Container base: `gcr.io/distroless/base` (via `rules_oci`).
