# wires-host Docker deploy — design

**Date:** 2026-05-18
**Status:** design, not yet implemented
**Scope:** package `wires-host` as a Docker image, run it under Docker Compose on a single Linux host (`workbench`), and provide two operator scripts: one to build + roll out a new version, one to manage the Tailscale Funnel that publishes the host ticket HTTP page.

## Goals

1. A persistently-running `wires-host` on a single Linux machine, surviving reboots and image upgrades without losing its iroh identity or tenant data.
2. A repeatable build that takes advantage of cargo-chef's dependency-layer caching, so changing a line in `wires-host` does not re-pull or rebuild iroh / redb / rustls.
3. The ticket HTTP page reachable from the public internet via Tailscale Funnel, terminated by Tailscale (no HTTPS in-container).
4. Operator workflow: pull, build, roll over with a single command on the deploy host; bring up Funnel once with another single command.

## Non-goals

- Multi-arch images. Single-host means single-arch (whatever `workbench` is, likely linux/amd64).
- CI / registry publishing. Image stays local-only (`wires-host:local`).
- HTTPS termination inside the container. Tailscale Funnel handles it.
- Healthcheck endpoint. `wires-host` has no `/healthz` yet; `restart: unless-stopped` is sufficient for v1.
- Automated backups, secret rotation, alerting.
- Image tagging / rollback story. The script always builds from the working tree and tags `:local`.
- Code changes to `wires-host` itself. This is purely operational packaging.

## Repository layout

A new top-level `docker/` directory:

```
docker/
  Dockerfile               # multi-stage with cargo-chef
  Dockerfile.dockerignore  # BuildKit reads this when -f docker/Dockerfile is used
  compose.yaml             # single service: wires-host
  deploy.sh                # build + roll out
  funnel.sh                # up / down / status for Tailscale Funnel
  README.md                # walkthrough
```

`docker/` is the build context root for the compose file's `build:` block via `context: ..`, so the Dockerfile sees the whole workspace.

## Dockerfile

Four stages.

### `chef` stage

```
FROM lukemathwalker/cargo-chef:latest-rust-1-bookworm AS chef
WORKDIR /app
```

Bookworm to match the runtime base. The image ships rustup, so `rust-toolchain.toml`'s `channel = "stable"` installs the current stable on first `cargo` invocation — no need to pin the base image to a specific Rust point release.

### `planner` stage

```
FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json
```

Emits `recipe.json` describing every workspace dependency. Source files are not promoted further.

### `builder` stage

```
FROM chef AS builder
COPY --from=planner /app/recipe.json recipe.json
RUN cargo chef cook --release -p wires-host --recipe-path recipe.json
COPY . .
RUN cargo build --release -p wires-host
```

The two-step `cook` then `COPY . .` is the load-bearing detail: `cargo chef cook` builds only the dependencies, so changing any non-dep source file (everything in `crates/`) reuses the cached deps layer instead of recompiling iroh.

### `runtime` stage

```
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
```

`ca-certificates` is installed because rustls trusts the system store via `rustls-native-certs` (transitively pulled in by `reqwest` / `iroh`). `EXPOSE 8089/tcp` is informational only since the container runs with host networking.

The `wires` user owns `/data`; the named volume inherits that ownership on first mount because the directory is created during image build before the volume is attached.

### Dockerfile.dockerignore

The file lives at `docker/Dockerfile.dockerignore`, the per-Dockerfile sidecar location that BuildKit reads when `docker build -f docker/Dockerfile <context>` is invoked. A plain `docker/.dockerignore` would be silently ignored (Docker reads `.dockerignore` from the *context* root, not from the Dockerfile's directory) — using the `<dockerfile-name>.dockerignore` convention keeps the exclusion list co-located with the Dockerfile while remaining honored by BuildKit.

```
target/
data/
Wires/
.git/
docs/
*.md
.DS_Store
```

Excludes the macOS Xcode app (`Wires/`), local data fixtures, the host's prior `target/` build artifacts, and docs that don't influence the build. `.git/` is excluded because cargo-chef doesn't need it and `git describe`-style versioning is out of scope.

## compose.yaml

```yaml
services:
  wires-host:
    build:
      context: ..
      dockerfile: docker/Dockerfile
    image: wires-host:local
    container_name: wires-host
    network_mode: host
    volumes:
      - wires-host-data:/data
    restart: unless-stopped
    environment:
      RUST_LOG: "warn,wires_host=info,wires_net=info,wires_node=info"
    stop_signal: SIGINT
    stop_grace_period: 10s

volumes:
  wires-host-data:
    name: wires-host-data
```

### Design notes

- **`network_mode: host`** — iroh binds UDP directly on the host's interfaces (no Docker NAT), and the ticket HTTP page is reachable on `127.0.0.1:8089` so `tailscale funnel` (also running on the host) can proxy it without any port-publish dance. Tradeoff: the container shares the host's network namespace; this is acceptable on a dedicated single-tenant deploy host.
- **Named volume `wires-host-data`** — Docker manages the volume. It persists `iroh.secret`, `tenants.redb`, `topic_index.redb`, `nonces.redb`, and the `tenants/<root>/` subtree across container recreates and image rebuilds. Backups are taken by running a one-shot container that mounts the volume.
- **`restart: unless-stopped`** — survives reboots; respects an explicit `docker compose down`.
- **`stop_signal: SIGINT`** — compose's default `SIGTERM` is not caught by `wires-host` today (its shutdown task only listens on `tokio::signal::ctrl_c()`, i.e. `SIGINT`). Overriding the stop signal lets the existing shutdown path drain cleanly without a code change. A future cleanup could add a proper `SIGTERM` handler in `wires-host` and drop this override.
- **`stop_grace_period: 10s`** — generous window for redb to flush and iroh to close cleanly after `SIGINT`.
- **`RUST_LOG`** — matches the binary's own default filter; surfaced as an env var so operators can override (`RUST_LOG=debug docker compose up`) without rebuilding.

## deploy.sh

`docker/deploy.sh`. Operator runs it on `workbench` from any path inside the repo. Designed to be idempotent.

```bash
#!/usr/bin/env bash
set -euo pipefail

PULL=1
VERIFY=1
for arg in "$@"; do
  case "$arg" in
    --no-pull)   PULL=0 ;;
    --no-verify) VERIFY=0 ;;
    -h|--help)
      echo "Usage: $(basename "$0") [--no-pull] [--no-verify]"
      exit 0 ;;
    *)
      echo "unknown flag: $arg" >&2
      exit 64 ;;
  esac
done

cd "$(git rev-parse --show-toplevel)"

if [[ "$PULL" -eq 1 ]]; then
  git fetch --tags origin
  git pull --ff-only
fi

SHA="$(git rev-parse --short HEAD)"
echo "==> deploying wires-host at $SHA"

docker compose -f docker/compose.yaml build
docker compose -f docker/compose.yaml up -d

if [[ "$VERIFY" -eq 1 ]]; then
  echo "==> waiting for ticket HTTP on :8089"
  for _ in $(seq 1 15); do
    if curl -fsS -o /dev/null http://127.0.0.1:8089/; then
      echo "==> ticket HTTP up"
      break
    fi
    sleep 1
  done
  if ! curl -fsS -o /dev/null http://127.0.0.1:8089/; then
    echo "!! ticket HTTP did not come up; recent logs:" >&2
    docker compose -f docker/compose.yaml logs --tail=200 wires-host >&2
    exit 1
  fi
fi

echo "==> current ticket:"
docker compose -f docker/compose.yaml exec -T wires-host \
  wires-host --data-dir /data ticket --no-qr
```

### Flags

- `--no-pull` — skip `git fetch` / `git pull`. Useful for testing local uncommitted changes.
- `--no-verify` — skip the HTTP poll. Required if the host is ever run with `--no-http`; we don't expect that on `workbench`, but the flag keeps the script honest.

### Remote invocation

From a developer machine:

```bash
ssh workbench 'bash -lc "cd ~/src/wires && ./docker/deploy.sh"'
```

This one-liner lives in `docker/README.md`. No separate remote script.

## funnel.sh

`docker/funnel.sh`. Subcommands: `up`, `down`, `status`. Runs on `workbench`.

```bash
#!/usr/bin/env bash
set -euo pipefail

PORT="${WIRES_HOST_HTTP_PORT:-8089}"

usage() {
  cat <<EOF
Usage: $(basename "$0") <up|down|status>

  up      Publish http://127.0.0.1:$PORT via Tailscale Funnel on :443.
  down    Tear down the Funnel mapping on :443.
  status  Print current serve/funnel configuration.

Environment:
  WIRES_HOST_HTTP_PORT  Override the local port (default: 8089).
EOF
}

require_tailscale() {
  command -v tailscale >/dev/null 2>&1 \
    || { echo "tailscale CLI not on PATH" >&2; exit 1; }
  tailscale status --self=true --peers=false >/dev/null 2>&1 \
    || { echo "tailscale is not logged in; run 'sudo tailscale up' first" >&2; exit 2; }
}

case "${1:-}" in
  up)
    require_tailscale
    sudo tailscale funnel --bg --https=443 --set-path=/ "http://127.0.0.1:$PORT"
    sudo tailscale funnel status
    ;;
  down)
    require_tailscale
    sudo tailscale funnel reset
    ;;
  status)
    require_tailscale
    sudo tailscale funnel status
    ;;
  *)
    usage; exit 64 ;;
esac
```

### Prerequisites the script does not handle

- The tailnet admin policy must grant `funnel: ["*"]` to this node (admin panel toggle).
- HTTPS certs must be enabled for the tailnet (admin panel toggle).
- Tailscale must already be installed and logged in (`sudo tailscale up`).

If any of these are missing, the underlying `tailscale` invocation prints a clear error and the script exits non-zero.

### Why a separate script

Funnel setup is a one-time install action, not per-rollout. Bundling it into `deploy.sh` would mean every rollover poked at the Tailscale state, which is unnecessary and slightly surprising. The container's `127.0.0.1:8089` listener is stable across rollovers — once Funnel points at it, it stays valid.

## docker/README.md

A short walkthrough covering:

1. **First-time install on `workbench`.**
   - Clone `~/src/wires`.
   - Ensure Tailscale is up; ensure Funnel + HTTPS are enabled in the admin panel.
   - `./docker/deploy.sh` — builds and starts the container; prints the host ticket.
   - `./docker/funnel.sh up` — publishes the ticket page on the public Funnel URL.
2. **Subsequent rollouts.** `./docker/deploy.sh` (optionally `--no-pull` for local changes).
3. **Inspect.**
   - `docker compose -f docker/compose.yaml logs -f wires-host`
   - `docker compose -f docker/compose.yaml exec wires-host wires-host --data-dir /data ticket --no-qr`
4. **Backup.**
   ```bash
   docker run --rm -v wires-host-data:/src -v "$PWD:/out" debian:bookworm-slim \
     tar -C /src -czf "/out/wires-host-$(date +%F).tgz" .
   ```
5. **Restore.** Inverse: `tar -xzf … -C /src` into the same named volume.
6. **Remote invocation from a developer machine.** The `ssh workbench 'bash -lc "cd ~/src/wires && ./docker/deploy.sh"'` one-liner.

## Operational details

### First-boot identity

On first start, `wires-host` runs `load_or_create_secret("/data/iroh.secret")` and writes a fresh 32-byte key. The same call returns the existing key on every subsequent start, so the host's `EndpointId` is stable for the lifetime of the volume. Losing or replacing the volume changes the EndpointId — any tenant that paired against the old ticket will need to re-pair.

### Reading the ticket

Three equivalent ways:
- `docker compose logs wires-host | grep 'host ticket:'` — emitted on every start.
- `docker compose exec wires-host wires-host --data-dir /data ticket --no-qr` — re-prints on demand without restarting.
- The Funnel URL — visiting it returns the ticket HTTP page rendered by `ticket_http.rs`.

`deploy.sh` prints the ticket at the end of each successful rollout to make the third-of-three case unnecessary for the common operator flow.

### Shutdown ordering

`docker compose down` sends the signal configured via `stop_signal` (here, `SIGINT`); `wires-host` catches it via `tokio::signal::ctrl_c()`, cancels the `CancellationToken`, waits for the HTTP task to drain, and exits. redb flushes synchronously on `Drop`. The 10-second `stop_grace_period` is well above the observed flush time of any test workload.

### Tracing output

`tracing-subscriber::fmt` writes human-formatted lines to stderr. Docker captures those via its logging driver (default `json-file`). No code changes; structured JSON logging is a possible future enhancement if log aggregation is added.

## Risks and tradeoffs

1. **`network_mode: host` weakens container isolation.** On a dedicated single-tenant deploy host this is acceptable. If the host ever becomes multi-tenant for unrelated services, this should be revisited (bridge networking + explicit `ports:` for `8089/tcp` plus careful UDP forwarding for iroh).
2. **No image tagging or rollback.** A bad deploy is fixed by reverting the repo and re-running `deploy.sh`. There's no quick way to flip back to the prior image without a rebuild. Future enhancement: tag images `:<sha>` and `:latest`, retain the last N, and add `deploy.sh --rollback <sha>`.
3. **Build host requirements.** Compiling iroh + the workspace under release uses ~3GB peak RAM and several minutes of CPU on first run. cargo-chef makes subsequent builds fast but does not change the cold-start cost.
4. **Volume-as-source-of-identity.** The named volume holds the only copy of `iroh.secret` and all tenant data. Operators must take backups before doing anything destructive (e.g., `docker volume rm`).

## Acceptance criteria

- `docker compose -f docker/compose.yaml build` succeeds from a clean checkout.
- `docker compose -f docker/compose.yaml up -d` starts the container; `wires-host: running. Press Ctrl-C to exit.` appears in `docker compose logs`.
- The host ticket prints in logs on every start and via `docker compose exec wires-host wires-host --data-dir /data ticket --no-qr`.
- After `docker compose down && docker compose up -d`, the host's `EndpointId` is unchanged (the volume preserved `iroh.secret`).
- After `./docker/funnel.sh up`, visiting the Funnel URL returns the ticket HTTP page.
- After a code change in `wires-host` and a re-run of `deploy.sh`, the rebuild is faster than the initial cold build (cargo-chef cache hit on the deps layer).
