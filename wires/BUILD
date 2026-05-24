# gazelle:ignore

load("@rules_rust//rust:defs.bzl", "rust_binary", "rust_test")

# The main multi-call binary: //wires
rust_binary(
    name = "wires",
    srcs = glob(["*.rs"]),
    edition = "2024",
    visibility = ["//visibility:public"],
    deps = [
        "//library",
        "@crates//:anyhow",
        "@crates//:clap",
        "@crates//:iroh",
        "@crates//:tokio",
    ],
)

rust_test(
    name = "wires_test",
    crate = ":wires",
    deps = ["@crates//:proptest"],
)
