# gazelle:ignore

load("@rules_rust//rust:defs.bzl", "rust_binary", "rust_test")
load("//tools/oci:rust_image.bzl", "rust_image")

WIRES_DEPS = [
    "//library",
    "@crates//:anyhow",
    "@crates//:base64",
    "@crates//:clap",
    "@crates//:futures-core",
    "@crates//:iroh",
    "@crates//:iroh-gossip",
    "@crates//:redb",
    "@crates//:reqwest",
    "@crates//:ring",
    "@crates//:rustls",
    "@crates//:serde",
    "@crates//:serde_json",
    "@crates//:tokio",
    "@crates//:tracing",
    "@crates//:tracing-subscriber",
    "@crates//:url",
]

# The main multi-call binary: //wires
rust_binary(
    name = "wires",
    srcs = glob(["*.rs"]),
    edition = "2024",
    visibility = ["//visibility:public"],
    deps = WIRES_DEPS,
)

# Dev-only build of the same crate with the hidden `dev-mock-idp` subcommand
# (a hermetic loopback OIDC issuer) for `.scripts/demo-remote-cli.sh`. Never
# packaged: the image and releases use `:wires`, which does not compile the mock.
rust_binary(
    name = "wires_dev",
    srcs = glob(["*.rs"]),
    crate_features = ["dev-mock-idp"],
    crate_name = "wires",
    crate_root = "main.rs",
    edition = "2024",
    deps = WIRES_DEPS,
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
