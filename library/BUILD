# gazelle:ignore

load("@rules_rust//rust:defs.bzl", "rust_doc_test", "rust_library", "rust_test")

_DEPS = [
    "@crates//:base64",
    "@crates//:blake3",
    "@crates//:ed25519-dalek",
    "@crates//:hex",
    "@crates//:rand",
    "@crates//:serde",
    "@crates//:serde_json",
    "@crates//:thiserror",
]

# The shared library crate: //library (crate name `library`).
rust_library(
    name = "library",
    srcs = glob(["*.rs"]),
    edition = "2024",
    visibility = ["//visibility:public"],
    deps = _DEPS,
)

rust_test(
    name = "library_test",
    crate = ":library",
    deps = ["@crates//:proptest"],
)

rust_doc_test(
    name = "library_doc_test",
    crate = ":library",
)
