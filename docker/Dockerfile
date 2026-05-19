# docker/Dockerfile
# syntax=docker/dockerfile:1.7

# --- chef: provides cargo-chef on Debian Bookworm with stable Rust ---------
FROM lukemathwalker/cargo-chef:latest-rust-1-bookworm AS chef
WORKDIR /app

# --- planner: produces a recipe describing every dependency ----------------
FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

# --- builder: pre-builds deps from the recipe, then builds wires-host ------
FROM chef AS builder
COPY --from=planner /app/recipe.json recipe.json
# Cook the union of deps required by wires-host and wires-mcp; the cached
# layer is invalidated only when recipe.json changes (i.e. workspace deps
# shift), not on source-only edits to either binary.
RUN cargo chef cook --release --locked \
    -p wires-host -p wires-mcp --recipe-path recipe.json
COPY . .
# Single `cargo build` invocation so both binaries share the same workspace
# crate cache; two separate invocations would recompile every shared crate
# (wires-core, wires-crypto, wires-store, wires-net, wires-node) twice.
RUN cargo build --release --locked -p wires-host -p wires-mcp

# Shared runtime base: debian-slim, ca-certificates, non-root `wires` user.
# Both runtime-host and runtime-mcp build on top of this to avoid duplication.
FROM debian:bookworm-slim AS runtime-base
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates \
 && rm -rf /var/lib/apt/lists/*
RUN useradd --system --uid 10001 --create-home --home-dir /data --shell /usr/sbin/nologin wires
USER wires
WORKDIR /data

# Final image for wires-host. Compose selects this with `build.target: runtime-host`.
FROM runtime-base AS runtime-host
COPY --from=builder /app/target/release/wires-host /usr/local/bin/wires-host
EXPOSE 10000/tcp
ENTRYPOINT ["wires-host"]
CMD ["--data-dir", "/data"]

# Final image for wires-mcp. Compose selects this with `build.target: runtime-mcp`.
FROM runtime-base AS runtime-mcp
COPY --from=builder /app/target/release/wires-mcp /usr/local/bin/wires-mcp
EXPOSE 10001/tcp
ENTRYPOINT ["wires-mcp"]
CMD ["serve"]
