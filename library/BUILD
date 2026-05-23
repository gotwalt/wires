# gazelle:ignore

load("@rules_rust//rust:defs.bzl", "rust_library", "rust_test")

# The shared library crate: //library (crate name `library`).
rust_library(
    name = "library",
    srcs = glob(["*.rs"]),
    edition = "2024",
    visibility = ["//visibility:public"],
    deps = [
        "@crates//:ed25519-dalek",
        "@crates//:serde",
        "@crates//:thiserror",
    ],
)

rust_test(
    name = "library_test",
    crate = ":library",
)
