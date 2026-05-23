# gazelle:ignore

load("@rules_rust//rust:defs.bzl", "rust_binary")

# The self-hosted rendezvous relay: //relay:wires-relay
rust_binary(
    name = "wires-relay",
    srcs = glob(["*.rs"]),
    edition = "2024",
    visibility = ["//visibility:public"],
    deps = [
        "//library",
        "@crates//:clap",
    ],
)
