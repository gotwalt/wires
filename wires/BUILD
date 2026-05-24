# gazelle:ignore

load("@rules_rust//rust:defs.bzl", "rust_binary", "rust_test")
load("//tools/oci:rust_image.bzl", "rust_image")

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
        "@crates//:serde",
        "@crates//:serde_json",
        "@crates//:tokio",
        "@crates//:tracing",
        "@crates//:tracing-subscriber",
    ],
)

rust_test(
    name = "wires_test",
    crate = ":wires",
    deps = ["@crates//:proptest"],
)

# Distroless OCI image of the `wires` binary: //wires:image (+ //wires:image.load).
# Self-contained for the dialer/shim side (`wires connect`); for a responder,
# compose an image that also contains the tool/MCP-server binary it execs.
rust_image(
    name = "image",
    binary = ":wires",
)
