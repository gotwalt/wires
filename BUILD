"""Targets in the repository root"""

load("@gazelle//:def.bzl", "gazelle")

exports_files(
    [
        ".editorconfig",
        ".shellcheckrc",
        ".clippy.toml",
    ],
    visibility = ["//:__subpackages__"],
)

# We prefer BUILD instead of BUILD.bazel
# gazelle:build_file_name BUILD
# gazelle:exclude .githooks/*

# Starlark BUILD maintenance (the only language handled by the Aspect CLI
# gazelle here). Rust BUILD generation is handled by gazelle_rust below.
gazelle(
    name = "gazelle",
    env = {
        "ENABLE_LANGUAGES": "starlark",
    },
    gazelle = "@multitool//tools/gazelle",
)

# Rust BUILD file generation via gazelle_rust.
# Uses a separate gazelle binary since the Aspect CLI multitool binary does not include Rust.
# Run with: bazel run //:gazelle_rust
#
# Per-crate BUILD files are hand-written and marked `# gazelle:ignore` (see
# //library, //wires, //relay) — gazelle_rust is kept available but does not own
# them. These directives configure dependency resolution if it is ever run.
# gazelle:rust_cargo_lockfile Cargo.lock
# gazelle:rust_crates_prefix @crates//:
# gazelle:rust_default_edition 2024

gazelle(
    name = "gazelle_rust",
    gazelle = "@gazelle_rust//:gazelle_bin",
)
