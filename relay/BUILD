# gazelle:ignore

load("@rules_rust//rust:defs.bzl", "rust_binary")
load("//tools/oci:rust_image.bzl", "rust_image")

# The self-hosted rendezvous relay: //relay:relay
rust_binary(
    name = "relay",
    srcs = glob(["*.rs"]),
    edition = "2024",
    visibility = ["//visibility:public"],
    deps = [
        "@crates//:anyhow",
        "@crates//:clap",
        "@crates//:iroh-relay",
        "@crates//:tokio",
        "@crates//:tracing",
        "@crates//:tracing-subscriber",
    ],
)

# Distroless OCI image: //relay:image (and //relay:image.load for `docker load`).
rust_image(
    name = "image",
    binary = ":relay",
)
