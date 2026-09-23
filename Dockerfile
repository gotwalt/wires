# syntax=docker/dockerfile:1
#
# The `wires` binary in a distroless image. Builds natively on whatever
# architecture the Docker host is (arm64 on a Mac, x86_64 on workbench): no
# cross-compiling. `docker build -t wires .` (or `make image`).
#
# The image holds only `wires` — enough for the caller side (`wires call`,
# `wires mcp`, `wires watch`). A host that exposes CLIs needs those CLIs too:
# build FROM this image's builder stage, or copy /usr/local/bin/wires into an
# image that already has them.

FROM rust:1.91.0-bookworm AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY library ./library
COPY wires ./wires
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --release --locked -p wires \
    && cp target/release/wires /usr/local/bin/wires

FROM gcr.io/distroless/cc-debian12:nonroot
COPY --from=build /usr/local/bin/wires /usr/local/bin/wires
ENTRYPOINT ["/usr/local/bin/wires"]
