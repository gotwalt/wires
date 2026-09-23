# Rust Crate Layout for Bazel + Gazelle

> **Archived 2026-09-22.** Superseded by CLAUDE.md: packages are flat with hand-written `# gazelle:ignore` BUILD files, so the gazelle_rust sub-package scheme below no longer applies.

## Problem

`gazelle_rust` scans for `.rs` files and generates BUILD files in every directory
containing them. When a Rust crate uses nested directories (e.g. `node/src/dag/`),
gazelle creates BUILD files in each subdirectory. These BUILD files create Bazel
**package boundaries**, which:

1. Prevent a parent BUILD's `glob()` from reaching into child packages.
2. Claim ownership of the `.rs` files, conflicting with the parent's `rust_library`.

Adding `# gazelle:ignore` to the parent BUILD only prevents gazelle from modifying
*that* BUILD — it does not stop gazelle from discovering and generating BUILD files
in subdirectories.

## Solution: Bazel Sub-packages

Split logical modules into proper Bazel sub-packages — each a separate Rust crate
with its own `BUILD`, `Cargo.toml`, and `lib.rs`. A thin facade crate re-exports
the sub-crates so that downstream consumers see a single `wires::` namespace.

This gives fine-grained dependency declarations and faster incremental builds while
preserving the existing import paths.

### Directory layout

For a crate `wires/` with module `core`:

```
wires/
├── BUILD              # facade: rust_library "amr_node" depending on 4 sub-crates
├── Cargo.toml         # path deps on 4 sub-crates
├── lib.rs             # pub use core; ...
├── core/
│   ├── BUILD          # rust_library "dag"
│   ├── Cargo.toml     # [package] name = "dag"
│   ├── lib.rs         # pub mod types, hash, dvv, builder
│   └── builder.rs
└── server/
    └── ...            # binary crate, depends on //wires:core facade
```

### Facade crate

The parent `wires/lib.rs` is a thin re-export layer:

```rust
pub use core;
```

Downstream code continues to use `wires::core::types::*` etc.
with zero import changes.

### Cross-crate imports

Within sub-crates, references to sibling crates use the crate name directly
(not `crate::` paths):

| Context | Import style |
|---|---|
| Within `core/` referring to own modules | `crate::name::thing` |

### Sub-crate BUILD file

Each sub-crate's BUILD is `# gazelle:ignore` and hand-maintained:

```python
# gazelle:ignore

load("@rules_rust//rust:defs.bzl", "rust_library", "rust_test")

_SRCS = glob(["*.rs"])

_DEPS = [
    "//wirss/core",        # sibling sub-crate deps
    "@crates//:redb",    # external deps
]

rust_library(
    name = "store",
    srcs = _SRCS,
    edition = "2024",
    visibility = ["//visibility:public"],
    deps = _DEPS,
)

rust_test(
    name = "store_test",
    crate = ":store",
)
```

### Cargo.toml

Each sub-crate uses a short package name matching the lib name and references
siblings via path deps:

```toml
[package]
name = "store"
version = "0.1.0"
edition = "2024"

[lib]
name = "store"
path = "lib.rs"

[dependencies]
dag = { path = "../dag" }
redb = "2.4"
```

The root `Cargo.toml` workspace must list all sub-crate members:

```toml
[workspace]
resolver = "2"
members = [
    "wires",
    "wires/core",
]
```

## What to do after running `gazelle_rust`

If you accidentally run `gazelle_rust` and it generates BUILD files inside
hand-maintained sub-crate directories, restore the originals from git:

```bash
git checkout -- wires/core/BUILD
```
