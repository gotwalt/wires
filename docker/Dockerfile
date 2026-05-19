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
# Cook only the deps required by wires-host; this layer is cached as long
# as recipe.json is unchanged (i.e. workspace deps haven't shifted).
RUN cargo chef cook --release --locked -p wires-host --recipe-path recipe.json
COPY . .
RUN cargo build --release --locked -p wires-host

# --- runtime: minimal Debian with the binary and a non-root user -----------
FROM debian:bookworm-slim AS runtime
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates \
 && rm -rf /var/lib/apt/lists/*
RUN useradd --system --uid 10001 --create-home --home-dir /data --shell /usr/sbin/nologin wires
COPY --from=builder /app/target/release/wires-host /usr/local/bin/wires-host
USER wires
WORKDIR /data
EXPOSE 8089/tcp
ENTRYPOINT ["wires-host"]
CMD ["--data-dir", "/data"]
