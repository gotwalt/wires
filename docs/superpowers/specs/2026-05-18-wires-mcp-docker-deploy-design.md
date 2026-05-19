# wires-mcp Docker deploy — design

**Date:** 2026-05-18
**Status:** design, not yet implemented
**Scope:** add `wires-mcp` as a second service in the existing `docker/compose.yaml`, alongside `wires-host`. Multi-binary Dockerfile, separate named volume, operator-edited TOML config, Tailscale Funnel on `:443` for public HTTPS.

**Predecessor:** `docs/superpowers/specs/2026-05-18-wires-host-docker-deploy-design.md`. This spec adds to it; the baseline rationale (`network_mode: host`, cargo-chef build, `stop_signal: SIGINT`, named-volume persistence, single-host operator workflow) carries over without restatement.

## Goals

1. Run `wires-mcp` as a second compose service on the same Linux host as `wires-host`.
2. One Dockerfile that builds both binaries with maximum cargo-chef cache reuse.
3. Persistent state in a separate named volume `wires-mcp-data` (gateway DB, token signing key, per-user wires agent dirs, in-flight pair-listen state).
4. Operator config managed as a host-side TOML mounted read-only into the container; a committed `.example` template + a gitignored real copy.
5. Public HTTPS via Tailscale Funnel on `:443`, mapping to `127.0.0.1:10001` (wires-mcp's local listen).
6. `deploy.sh` and `funnel.sh` extended to manage both services in one workflow.

## Non-goals

- Code changes to `wires-mcp`. (Two known gaps with the binary are noted as follow-ups, not blockers.)
- Multi-arch images. Still single-arch (workbench).
- CI / registry publishing.
- Wires-internal pairing scaffolding. `wires-mcp` joins each user's chosen host as a normal wires agent via the responder pair flow; that is in-binary behavior and not a Docker concern.
- Reverse-proxy auth, mTLS, IP allowlists, or rate-limit knobs at the proxy layer. Funnel sits in front; everything below is wires-mcp's own job.
- `:8443` and the existing `:3001`/`:3002` services on workbench. We reclaim Funnel `:443`; the existing tailnet-only serve on `:8443` is left alone.

## Funnel port assignment

| Funnel port | Maps to | Service |
|---|---|---|
| `:443` (Funnel) | `127.0.0.1:10001` | wires-mcp |
| `:10000` (Funnel) | `127.0.0.1:10000` | wires-host ticket |
| `:8443` (tailnet-only serve) | `127.0.0.1:3002` | unchanged, not wires |

wires-mcp gets `:443` because its OAuth issuer URL becomes part of every JWT (`iss`, `aud`, RFC 8707 `resource`) and clean URLs without a port are friendlier for OAuth clients and tokens that may outlive port-numbering decisions. The existing Funnel `:443` mapping to `127.0.0.1:3001` is removed; the service there responds to TCP connect but returns no HTTP, so reclamation has no observable impact.

**Load-bearing consequence:** once wires-mcp issues tokens with `iss = https://workbench.tail63ef5.ts.net`, that URL must remain stable. Renaming workbench in the tailnet, or moving wires-mcp to a different host, invalidates every outstanding token and forces every OAuth client to re-authorize.

## Local port convention

| Local port | Service |
|---|---|
| `127.0.0.1:10000` | wires-host ticket HTTP (compose override of binary default `:8089`) |
| `127.0.0.1:10001` | wires-mcp HTTP (set via the TOML `bind` field) |
| `127.0.0.1:10002+` | reserved for future wires-* services |

Contiguous, non-privileged. The Funnel public port and the local port are decoupled — Funnel always reverse-proxies — so the local 10000+ scheme is independent of Tailscale's 3-port public limit.

## Repository layout (delta)

```
docker/
  Dockerfile                 # edited: two runtime stages
  Dockerfile.dockerignore    # unchanged
  compose.yaml               # edited: adds wires-mcp service
  wires-mcp.toml.example     # NEW: operator template (committed)
  wires-mcp.toml             # NEW (gitignored, operator-edited): real config
  deploy.sh                  # edited: builds + ups + polls both
  funnel.sh                  # edited: host|mcp|all subarg
  README.md                  # edited: MCP setup section
.gitignore                   # edited: add docker/wires-mcp.toml
```

## Dockerfile

Four shared stages, two runtime targets.

```dockerfile
# syntax=docker/dockerfile:1.7

FROM lukemathwalker/cargo-chef:latest-rust-1-bookworm AS chef
WORKDIR /app

FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS builder
COPY --from=planner /app/recipe.json recipe.json
RUN cargo chef cook --release --locked \
    -p wires-host -p wires-mcp --recipe-path recipe.json
COPY . .
RUN cargo build --release --locked -p wires-host -p wires-mcp

# Shared runtime: debian + ca-certs + non-root user. Avoids duplication
# between the two final stages.
FROM debian:bookworm-slim AS runtime-base
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates \
 && rm -rf /var/lib/apt/lists/*
RUN useradd --system --uid 10001 --create-home --home-dir /data --shell /usr/sbin/nologin wires
USER wires
WORKDIR /data

FROM runtime-base AS runtime-host
COPY --from=builder /app/target/release/wires-host /usr/local/bin/wires-host
EXPOSE 10000/tcp
ENTRYPOINT ["wires-host"]
CMD ["--data-dir", "/data"]

FROM runtime-base AS runtime-mcp
COPY --from=builder /app/target/release/wires-mcp /usr/local/bin/wires-mcp
EXPOSE 10001/tcp
ENTRYPOINT ["wires-mcp"]
CMD ["serve"]
```

### Design notes

- **One `cargo chef cook` for both binaries.** Cooking deps for `-p wires-host -p wires-mcp` together gives the union of their dep trees. Subsequent rebuilds after a non-dep source change reuse the cached deps layer for both binaries.
- **One `cargo build` invocation.** Compiling both binaries in a single `cargo build` reuses the workspace's compiled crate cache; building them as two separate cargo invocations would recompile every shared dep crate (`wires-core`, `wires-crypto`, `wires-store`, `wires-net`, `wires-node`) twice.
- **`runtime-base` factored out.** The `apt-get … ca-certificates` + `useradd` is identical for both binaries; living in a shared base stage avoids drift.
- **No image tagging story.** Both targets land as `wires-host:local` and `wires-mcp:local`. Same single-host-deploy posture as the predecessor spec.

## compose.yaml

```yaml
services:
  wires-host:
    build:
      context: ..
      dockerfile: docker/Dockerfile
      target: runtime-host
    image: wires-host:local
    container_name: wires-host
    network_mode: host
    volumes:
      - wires-host-data:/data
    restart: unless-stopped
    environment:
      RUST_LOG: "warn,wires_host=info,wires_net=info,wires_node=info"
    command: ["--data-dir", "/data", "--http-bind", "0.0.0.0:10000"]
    stop_signal: SIGINT
    stop_grace_period: 10s

  wires-mcp:
    build:
      context: ..
      dockerfile: docker/Dockerfile
      target: runtime-mcp
    image: wires-mcp:local
    container_name: wires-mcp
    network_mode: host
    volumes:
      - wires-mcp-data:/data
      - ./wires-mcp.toml:/etc/wires-mcp/config.toml:ro
    restart: unless-stopped
    environment:
      WIRES_MCP_CONFIG: /etc/wires-mcp/config.toml
      RUST_LOG: "info,wires_mcp=info"
    stop_signal: SIGINT
    stop_grace_period: 10s

volumes:
  wires-host-data:
    name: wires-host-data
  wires-mcp-data:
    name: wires-mcp-data
```

### Design notes

- **`./wires-mcp.toml:/etc/wires-mcp/config.toml:ro`**. Relative path is relative to the compose file's directory (`docker/`), so the operator-edited config lives at `docker/wires-mcp.toml`. The mount is read-only — the binary cannot accidentally overwrite the operator's edits.
- **`WIRES_MCP_CONFIG=/etc/wires-mcp/config.toml`**. Matches the binary's default location, so the env var is technically redundant — but stating it explicitly in compose makes the config path discoverable without reading the source.
- **`RUST_LOG=info,wires_mcp=info`** is documentation-only today. `wires-mcp/src/main.rs` hardcodes `tracing_subscriber::fmt().with_env_filter("info").init()`, so the env var has no effect. Setting it anyway anticipates a future binary fix that switches to a `RUST_LOG`-aware filter.
- **No `depends_on:` between services.** wires-mcp does not need wires-host alive to start; it pairs with each user's chosen host (which may be a different host entirely) on demand. Independent startup keeps the dependency graph simple.
- **Separate named volume `wires-mcp-data`.** Holds `gateway.redb` (OAuth state), `token_signing.ed25519` (JWT signing key), `users/<root>/` per-user wires agent data, and `pending_pairs/`. Different layout from wires-host's volume; independent backup and restore.

## wires-mcp.toml.example

```toml
# wires-mcp gateway config — copy to docker/wires-mcp.toml and edit
# `public_url` to match your Funnel hostname before first deploy.
# The copy is gitignored and operator-specific; the example is committed.

# Public-facing base URL (no trailing slash). Used as `iss`, `aud`, and
# RFC 8707 `resource` on every issued JWT. Must be stable once tokens are
# in the wild — renaming workbench or moving wires-mcp invalidates every
# outstanding token.
public_url = "https://workbench.tail63ef5.ts.net"

# Where wires-mcp listens inside the container. Funnel reverse-proxies
# from public :443 to this address. Must match deploy.sh's verify poll.
bind = "127.0.0.1:10001"

# Filesystem root inside the container; backed by the wires-mcp-data
# named volume.
data_dir = "/data"
```

The `.example` extension is committed; `wires-mcp.toml` (without `.example`) is gitignored.

## deploy.sh changes

The existing script becomes:

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
      cat <<EOF
Usage: $(basename "$0") [--no-pull] [--no-verify]

  --no-pull    Skip git fetch/pull; deploy the current working tree.
  --no-verify  Skip the HTTP healthcheck polls.
EOF
      exit 0 ;;
    *)
      echo "unknown flag: $arg" >&2
      exit 64 ;;
  esac
done

cd "$(git rev-parse --show-toplevel)"

# Pre-flight: wires-mcp config must exist before `docker compose up` so the
# bind-mount succeeds. Fail clearly instead of letting Docker emit a cryptic
# mount error.
if [[ ! -f docker/wires-mcp.toml ]]; then
  echo "!! docker/wires-mcp.toml is missing." >&2
  echo "   Copy docker/wires-mcp.toml.example to docker/wires-mcp.toml" >&2
  echo "   and edit public_url before running ./docker/deploy.sh again." >&2
  exit 1
fi

if [[ "$PULL" -eq 1 ]]; then
  git fetch --tags origin
  git pull --ff-only
fi

SHA="$(git rev-parse --short HEAD)"
echo "==> deploying wires-host + wires-mcp at $SHA"

docker compose -f docker/compose.yaml build
docker compose -f docker/compose.yaml up -d

if [[ "$VERIFY" -eq 1 ]]; then
  for endpoint in \
    "http://127.0.0.1:10000/" \
    "http://127.0.0.1:10001/_health"; do
    echo "==> waiting for $endpoint"
    ok=0
    for _ in $(seq 1 15); do
      if curl -fsS -o /dev/null "$endpoint"; then
        ok=1; break
      fi
      sleep 1
    done
    if [[ "$ok" -ne 1 ]]; then
      echo "!! $endpoint did not come up; recent logs:" >&2
      docker compose -f docker/compose.yaml logs --tail=200 >&2
      exit 1
    fi
    echo "==> $endpoint up"
  done
fi

echo "==> current wires-host ticket:"
docker compose -f docker/compose.yaml exec -T wires-host \
  wires-host --data-dir /data ticket --no-qr
echo
```

### Design notes

- **Pre-flight config check** runs before `git pull` (so a missing config fails fast on every invocation, not just the first one).
- **wires-mcp verify probe** uses `/_health`, an unauthenticated endpoint that wires-mcp exposes specifically for liveness checks (returns the literal string `ok`). A 200 confirms the axum service is up and routing.
- **Combined log dump on failure.** `docker compose logs --tail=200` without a service argument dumps both containers, giving the operator full visibility regardless of which service failed to come up.
- **Ticket printing still only covers wires-host.** wires-mcp's analogous "what does this gateway expose?" surface is the OAuth issuer URL (already in the config) and the `/.well-known/oauth-protected-resource` response. No equivalent one-shot CLI command exists in wires-mcp today.

## funnel.sh changes

```bash
#!/usr/bin/env bash
set -euo pipefail

# Service catalog. Add an entry per wires service that needs Funnel.
# Format: <name> <funnel_https_port> <local_port> [<funnel_path>]
SERVICES=(
  "host  10000  10000  /"
  "mcp     443  10001  /"
)

usage() {
  cat <<EOF
Usage: $(basename "$0") <up|down|status> [host|mcp|all]

  up      Publish the given service(s) via Tailscale Funnel.
  down    Remove the given service(s)' Funnel mapping(s).
  status  Print current serve/funnel configuration.

Services:
$(for row in "${SERVICES[@]}"; do
    set -- $row; printf "  %-6s Funnel :%s -> 127.0.0.1:%s%s\n" "$1" "$2" "$3" "$4"
  done)
EOF
}

require_tailscale() { ... }   # unchanged

apply() {
  local action="$1" name="$2"
  for row in "${SERVICES[@]}"; do
    set -- $row
    local svc="$1" fport="$2" lport="$3" fpath="$4"
    if [[ "$name" != "all" && "$name" != "$svc" ]]; then continue; fi
    case "$action" in
      up)   sudo tailscale funnel --bg --https="$fport" --set-path="$fpath" \
              "http://127.0.0.1:$lport" ;;
      down) sudo tailscale funnel --https="$fport" --set-path="$fpath" off ;;
    esac
  done
}

case "${1:-}" in
  up|down)
    require_tailscale
    apply "$1" "${2:-all}"
    tailscale funnel status
    ;;
  status)
    require_tailscale
    tailscale funnel status
    ;;
  *)
    usage; exit 64 ;;
esac
```

### Design notes

- **`SERVICES` is the source of truth.** Adding a third wires service later means adding one line, nothing else.
- **`down` is targeted per service.** Removing `mcp` doesn't touch `host`'s mapping, and vice versa. The previous `tailscale funnel reset` blast-radius is gone.
- **Default service argument is `all`.** `./docker/funnel.sh up` (no service) brings up every entry in the catalog. Operator-friendly default for a single-host deploy.
- **No more `WIRES_FUNNEL_HTTPS_PORT` / `WIRES_FUNNEL_PATH` env vars.** The previous spec exposed those as escape hatches; with a per-service catalog, they're unnecessary. Each service's Funnel slot is a fixed deployment decision baked into the script.

## docker/README.md additions

A new section after "First-time install":

1. **Copy the template:** `cp docker/wires-mcp.toml.example docker/wires-mcp.toml` and edit `public_url` to match your tailnet hostname (e.g. `https://workbench.tail63ef5.ts.net`).
2. **Run deploy:** `./docker/deploy.sh` builds both images, starts both services, polls both endpoints.
3. **Bring up Funnel:** `./docker/funnel.sh up all`. This adds Funnel `:10000` → wires-host and Funnel `:443` → wires-mcp (overwriting any prior `:443` mapping). The MCP issuer URL is now reachable from the public internet.
4. **Verify MCP:** `curl https://workbench.tail63ef5.ts.net/_health` should return `ok`. As a deeper smoke test, `curl https://workbench.tail63ef5.ts.net/.well-known/oauth-protected-resource` returns the RFC 9728 PRM JSON.

The existing backup/restore section gains a parallel paragraph for `wires-mcp-data` (same `docker run … tar` recipe).

## Operational details

### MCP gateway data lifecycle

- **`token_signing.ed25519`** lives in `wires-mcp-data:/token_signing.ed25519`. Losing it invalidates every outstanding JWT. Treat it like `iroh.secret` on wires-host: critical, back up the volume.
- **`gateway.redb`** holds OAuth client registrations, auth sessions, refresh tokens, and revocation state. Persists across container recreates and image upgrades.
- **`users/<root>/`** is a normal wires agent data directory per OAuth-registered user. Same internal layout as a CLI-managed agent (identity keys, caps DB, per-topic logs).
- **`pending_pairs/`** is in-flight pair-listen state. Transient; ephemeral failure modes are recoverable by re-driving the pair flow.

### Reading what wires-mcp is doing

- `docker compose -f docker/compose.yaml logs -f wires-mcp` — tail logs.
- `docker compose -f docker/compose.yaml exec wires-mcp wires-mcp user-list` — list registered users (reads via the default config path inside the container).
- `docker compose -f docker/compose.yaml exec wires-mcp wires-mcp client-list` — list OAuth clients.

### Shutdown ordering

Same as wires-host: compose's `stop_signal: SIGINT` triggers wires-mcp's existing `tokio::signal::ctrl_c()` handler. 10s grace period covers redb flush and in-flight HTTP completion.

## Known follow-ups (out of scope for this spec)

1. **`wires-mcp` hardcodes its log filter.** `main.rs` calls `tracing_subscriber::fmt().with_env_filter("info").init()`. Should switch to the same `EnvFilter::from_default_env()`-style pattern wires-host uses so `RUST_LOG` actually takes effect.
2. **No analog to `wires-host ticket`.** A `wires-mcp info` (or similar) subcommand that prints the issuer URL, JWT signing kid, and registered-user count would help operators verify a deploy at a glance. Today they read the config and call `user-list`.

## Risks and tradeoffs

1. **Funnel `:443` reclamation is destructive to the previous `:3001` mapping.** Confirmed (with the operator) that `:3001` returns no HTTP, so the impact is observable-zero — but any future Funnel rule on `:443` would conflict. The spec records that wires-mcp owns `:443` going forward.
2. **Operator-edited `wires-mcp.toml` is gitignored.** Loss of the workbench filesystem (or a careless `git clean -dfx`) loses the config — the operator has to recreate it from `.example` and re-edit `public_url`. Acceptable for a single-host deploy.
3. **Two services share host networking.** Already a known tradeoff from the wires-host spec. With two services it doubles down on the single-tenant-host assumption.
4. **Both volumes hold cryptographic material.** `wires-host-data` has `iroh.secret`; `wires-mcp-data` has `token_signing.ed25519`. Backups must include both, and any operator with shell access to workbench can read either.

## Acceptance criteria

- `docker compose -f docker/compose.yaml build` from a clean checkout produces both `wires-host:local` and `wires-mcp:local` images.
- `./docker/deploy.sh` with `docker/wires-mcp.toml` present builds, starts both services, and verifies both endpoints respond.
- `./docker/deploy.sh` without `docker/wires-mcp.toml` fails fast with a message pointing at the `.example` template.
- `./docker/funnel.sh up all` produces two Funnel mappings: `:10000` → `:10000` and `:443` → `:10001`. `funnel status` shows both.
- `curl https://workbench.tail63ef5.ts.net/_health` returns `ok`; `curl https://workbench.tail63ef5.ts.net/.well-known/oauth-protected-resource` returns the RFC 9728 PRM JSON; `curl https://workbench.tail63ef5.ts.net:10000/` returns the host ticket HTML.
- After `docker compose down && docker compose up -d`, both volumes preserve their state: `wires-host`'s EndpointId is unchanged, `wires-mcp`'s `token_signing.ed25519` SHA256 is unchanged.
- `./docker/funnel.sh down mcp` removes only the MCP mapping; `funnel status` still shows the wires-host mapping.
