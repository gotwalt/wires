# gazelle:ignore

load("@rules_rust//rust:defs.bzl", "rust_binary")

# The main multi-call binary: //src:wires
rust_binary(
    name = "wires",
    srcs = glob(["*.rs"]),
    edition = "2024",
    visibility = ["//visibility:public"],
    deps = [
        "//library",
        "@crates//:clap",
    ],
)
