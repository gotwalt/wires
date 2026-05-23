load("@rules_rust//rust:defs.bzl", "rust_library", "rust_test")

rust_library(
    name = "wires_core",
    srcs = [
        "src/error.rs",
        "src/grant.rs",
        "src/identity.rs",
        "src/lib.rs",
        "src/policy.rs",
        "src/session.rs",
        "src/ticket.rs",
    ],
    compile_data = ["Cargo.toml"],
    visibility = ["//visibility:public"],
    deps = [
        "@crates//:ed25519-dalek",
        "@crates//:serde",
        "@crates//:thiserror",
    ],
)

rust_test(
    name = "smoke",
    srcs = ["tests/smoke.rs"],
    compile_data = ["Cargo.toml"],
    visibility = ["//visibility:public"],
    deps = [":wires_core"],
)
