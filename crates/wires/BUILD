load("@rules_rust//rust:defs.bzl", "rust_binary")

rust_binary(
    name = "wires",
    srcs = ["src/main.rs"],
    compile_data = ["Cargo.toml"],
    visibility = ["//visibility:public"],
    deps = [
        "//crates/wires-core:wires_core",
        "@crates//:clap",
    ],
)
